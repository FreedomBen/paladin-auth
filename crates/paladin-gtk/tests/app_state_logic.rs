// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic top-level `AppState` tests for `paladin-gtk`.
//!
//! Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" and
//! §"Vault interaction", `AppModel` owns the resolved vault path
//! plus one of the `Missing`, `Locked`, `Unlocked`, `UnlockedBusy`,
//! or `StartupError` states. The pure-logic state machine in
//! `paladin_gtk::app::state` shadows this lifecycle:
//!
//! * Startup runs `paladin_core::default_vault_path()` then
//!   `paladin_core::inspect(path)`; the resolution / inspect
//!   outcome routes through [`paladin_gtk::app::state::decide_state_from_path_resolution`]
//!   and [`paladin_gtk::app::state::decide_state_from_inspect`].
//! * `VaultStatus::Missing` → `AppState::Missing` (`InitDialog`).
//! * `VaultStatus::Encrypted` → `AppState::Locked` (`UnlockComponent`).
//! * `VaultStatus::Plaintext` → caller proceeds to `open`; the
//!   decision function returns `None`.
//! * Path-resolution or inspect failure → `AppState::StartupError`.
//! * Non-passphrase `open` failure routes through
//!   [`paladin_gtk::app::state::decide_state_from_open_error`] and
//!   `AppState::StartupError`; wrong-passphrase stays inline.
//! * `Unlocked → UnlockedBusy` when a vault-touching worker takes
//!   the `(Vault, Store)` pair; `UnlockedBusy → Unlocked` when the
//!   worker returns. Both transitions preserve the vault path.
//! * `Locked → Unlocked` on a successful unlock; `Missing → Unlocked`
//!   on a successful `InitDialog` completion; `Unlocked → Locked`
//!   on an auto-lock expiry.
//!
//! The state machine here is widget-free and `(Vault, Store)`-free
//! so the routing and transition rules can be exercised without a
//! display server or a real vault file. The `AppModel` carries the
//! live `(Vault, Store)` pair next to the state machine in an
//! `Option<(Vault, Store)>`, restored on every worker return per
//! §"In-flight effect ownership".

use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use paladin_core::{
    format_unsafe_permissions, AccountId, ErrorKind, PaladinError, PermissionSubject, Store, Vault,
    VaultLock, VaultMode, VaultStatus,
};

use paladin_gtk::add_account::{AddWorkerInput, QrWorkerInput};
use paladin_gtk::app::state::{
    apply_add_vault_install_inplace, apply_submit_add_inplace, apply_submit_rename_inplace,
    apply_submit_unlock_inplace, apply_unlock_dispatch_inplace, apply_unlock_failure_action,
    apply_unlock_vault_install_inplace, compose_add_worker_input, compose_qr_worker_input,
    compose_rename_worker_input, compose_unlock_dispatch, compose_unlock_worker_input,
    decide_state_from_inspect, decide_state_from_open_error, decide_state_from_path_resolution,
    decide_unlock_failure_action, decide_unlock_success_state, route_unlock_failure_effect,
    route_unlock_success_effect, route_unlock_worker_outcome, run_unlock_worker,
    should_drop_unlock_dialog_after, submit_add_app_state, submit_rename_app_state,
    submit_unlock_app_state, unlock_app_state_after, unlock_dialog_msg_after,
    unlock_final_app_state, AppState, OpenErrorOutcome, UnlockFailureAction, UnlockFailureEffect,
    UnlockSuccessEffect, UnlockWorkerEffect, UnlockWorkerInput,
};
use paladin_gtk::rename_dialog::RenameWorkerInput;
use paladin_gtk::startup_error::StartupErrorSource;
use paladin_gtk::unlock_dialog::{
    route_unlock_open_error, InlineError, UnlockDialogMsg, UnlockOpenRouting,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn vault_path() -> PathBuf {
    PathBuf::from("/home/test/.local/share/paladin/vault.bin")
}

fn unsafe_perms_err() -> PaladinError {
    PaladinError::UnsafePermissions {
        path: vault_path(),
        subject: PermissionSubject::VaultFile,
        actual_mode: "0644".to_string(),
        expected_mode: "0600".to_string(),
    }
}

fn invalid_header_err() -> PaladinError {
    PaladinError::InvalidHeader
}

fn wrong_vault_lock_err() -> PaladinError {
    PaladinError::WrongVaultLock {
        expected: VaultMode::Encrypted,
        actual: VaultMode::Plaintext,
    }
}

fn invalid_payload_err() -> PaladinError {
    PaladinError::InvalidPayload {
        reason: "trailing_bytes",
    }
}

fn unsupported_format_version_err() -> PaladinError {
    PaladinError::UnsupportedFormatVersion { format_ver: 99 }
}

fn kdf_oob_err() -> PaladinError {
    PaladinError::KdfParamsOutOfBounds {
        m_kib: 4,
        t: 1,
        p: 1,
    }
}

fn io_err() -> PaladinError {
    PaladinError::IoError {
        operation: "read_vault",
        source: io::Error::new(io::ErrorKind::PermissionDenied, "no access"),
    }
}

fn path_resolution_io_err() -> PaladinError {
    PaladinError::IoError {
        operation: "resolve_default_vault_path",
        source: io::Error::new(io::ErrorKind::NotFound, "no platform home"),
    }
}

fn decrypt_failed_err() -> PaladinError {
    PaladinError::DecryptFailed
}

fn invalid_passphrase_empty_err() -> PaladinError {
    PaladinError::InvalidPassphrase {
        reason: "zero_length",
    }
}

fn assert_path_eq(state: &AppState, expected: &Path) {
    match state.path() {
        Some(p) => assert_eq!(
            p, expected,
            "state path should match the inspected vault path"
        ),
        None => panic!("expected state to carry vault path, got {state:?}"),
    }
}

// ---------------------------------------------------------------------------
// decide_state_from_inspect — VaultStatus routing
// ---------------------------------------------------------------------------

#[test]
fn inspect_missing_routes_to_missing_state() {
    let path = vault_path();
    let routed =
        decide_state_from_inspect(&path, Ok(VaultStatus::Missing)).expect("Missing yields state");
    assert!(matches!(routed, AppState::Missing { .. }));
    assert_path_eq(&routed, &path);
}

#[test]
fn inspect_encrypted_routes_to_locked_state() {
    let path = vault_path();
    let routed = decide_state_from_inspect(&path, Ok(VaultStatus::Encrypted))
        .expect("Encrypted yields state");
    assert!(matches!(routed, AppState::Locked { .. }));
    assert_path_eq(&routed, &path);
}

#[test]
fn inspect_plaintext_returns_none_to_proceed_to_open() {
    // Plaintext keeps the routing decision deferred to the caller:
    // the §"Vault interaction" rule is "Plaintext → call open
    // directly on the GTK main loop". `None` signals "proceed".
    let path = vault_path();
    let routed = decide_state_from_inspect(&path, Ok(VaultStatus::Plaintext));
    assert!(
        routed.is_none(),
        "Plaintext must return None so the caller invokes open; got {routed:?}"
    );
}

#[test]
fn inspect_unsafe_permissions_routes_to_startup_error_with_formatter_text() {
    let path = vault_path();
    let err = unsafe_perms_err();
    let expected_rendered =
        format_unsafe_permissions(&err).expect("UnsafePermissions has formatter text");
    let routed =
        decide_state_from_inspect(&path, Err(err)).expect("inspect Err yields StartupError state");
    match routed {
        AppState::StartupError {
            path: state_path,
            error,
        } => {
            assert_eq!(state_path.as_deref(), Some(path.as_path()));
            assert_eq!(error.source, StartupErrorSource::Inspect);
            assert_eq!(error.rendered, expected_rendered);
            assert_eq!(error.kind, ErrorKind::UnsafePermissions);
        }
        other => panic!("expected StartupError, got {other:?}"),
    }
}

#[test]
fn inspect_invalid_header_routes_to_startup_error() {
    let path = vault_path();
    let routed = decide_state_from_inspect(&path, Err(invalid_header_err()))
        .expect("inspect Err yields StartupError state");
    match routed {
        AppState::StartupError {
            path: state_path,
            error,
        } => {
            assert_eq!(state_path.as_deref(), Some(path.as_path()));
            assert_eq!(error.source, StartupErrorSource::Inspect);
            assert_eq!(error.kind, ErrorKind::InvalidHeader);
        }
        other => panic!("expected StartupError, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// decide_state_from_path_resolution
// ---------------------------------------------------------------------------

#[test]
fn path_resolution_ok_returns_none_to_proceed_to_inspect() {
    let routed = decide_state_from_path_resolution(Ok(vault_path()));
    assert!(
        routed.is_none(),
        "Ok(path) must return None so the caller proceeds to inspect; got {routed:?}"
    );
}

#[test]
fn path_resolution_err_routes_to_startup_error_with_no_path() {
    // `default_vault_path` failed before any path was resolved, so
    // the StartupError carries `path: None`; the AdwStatusPage
    // surface omits the path line in that case.
    let err = path_resolution_io_err();
    let routed = decide_state_from_path_resolution(Err(err))
        .expect("path resolution Err yields StartupError state");
    match routed {
        AppState::StartupError {
            path: state_path,
            error,
        } => {
            assert!(
                state_path.is_none(),
                "path-resolution failures carry no path; got {state_path:?}"
            );
            assert_eq!(error.source, StartupErrorSource::PathResolution);
            assert!(
                error.rendered.contains("resolve_default_vault_path"),
                "rendered text should mention the operation: {:?}",
                error.rendered
            );
        }
        other => panic!("expected StartupError, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// decide_state_from_open_error — wrong-passphrase stays inline; other errors
// transition to StartupError. Plaintext-path open errors flow through this
// helper too, since the routing rule is the same (passphrase decisions are
// vacuous on plaintext and never appear).
// ---------------------------------------------------------------------------

#[test]
fn open_decrypt_failed_stays_inline_on_passphrase_surface() {
    let path = vault_path();
    let outcome = decide_state_from_open_error(&path, &decrypt_failed_err());
    assert!(
        matches!(outcome, OpenErrorOutcome::InlinePassphrase),
        "DecryptFailed must stay inline; got {outcome:?}"
    );
}

#[test]
fn open_invalid_passphrase_stays_inline_on_passphrase_surface() {
    let path = vault_path();
    let outcome = decide_state_from_open_error(&path, &invalid_passphrase_empty_err());
    assert!(
        matches!(outcome, OpenErrorOutcome::InlinePassphrase),
        "InvalidPassphrase must stay inline; got {outcome:?}"
    );
}

#[test]
fn open_unsafe_permissions_routes_to_startup_error_with_formatter_text() {
    let path = vault_path();
    let err = unsafe_perms_err();
    let expected_rendered = format_unsafe_permissions(&err).expect("formatter text");
    match decide_state_from_open_error(&path, &err) {
        OpenErrorOutcome::Startup(state) => match state {
            AppState::StartupError {
                path: state_path,
                error,
            } => {
                assert_eq!(state_path.as_deref(), Some(path.as_path()));
                assert_eq!(error.source, StartupErrorSource::Open);
                assert_eq!(error.rendered, expected_rendered);
            }
            other => panic!("expected StartupError, got {other:?}"),
        },
        OpenErrorOutcome::InlinePassphrase => {
            panic!("unsafe_permissions must transition to StartupError")
        }
    }
}

#[test]
fn open_wrong_vault_lock_routes_to_startup_error() {
    let path = vault_path();
    let err = wrong_vault_lock_err();
    assert!(matches!(
        decide_state_from_open_error(&path, &err),
        OpenErrorOutcome::Startup(_)
    ));
}

#[test]
fn open_invalid_header_routes_to_startup_error() {
    let path = vault_path();
    assert!(matches!(
        decide_state_from_open_error(&path, &invalid_header_err()),
        OpenErrorOutcome::Startup(_)
    ));
}

#[test]
fn open_invalid_payload_routes_to_startup_error() {
    let path = vault_path();
    assert!(matches!(
        decide_state_from_open_error(&path, &invalid_payload_err()),
        OpenErrorOutcome::Startup(_)
    ));
}

#[test]
fn open_unsupported_format_version_routes_to_startup_error() {
    let path = vault_path();
    assert!(matches!(
        decide_state_from_open_error(&path, &unsupported_format_version_err()),
        OpenErrorOutcome::Startup(_)
    ));
}

#[test]
fn open_kdf_params_out_of_bounds_routes_to_startup_error() {
    let path = vault_path();
    assert!(matches!(
        decide_state_from_open_error(&path, &kdf_oob_err()),
        OpenErrorOutcome::Startup(_)
    ));
}

#[test]
fn open_io_error_routes_to_startup_error() {
    let path = vault_path();
    assert!(matches!(
        decide_state_from_open_error(&path, &io_err()),
        OpenErrorOutcome::Startup(_)
    ));
}

// ---------------------------------------------------------------------------
// AppState transitions: enter_busy / leave_busy
// ---------------------------------------------------------------------------

#[test]
fn unlocked_enters_busy_and_preserves_path() {
    let path = vault_path();
    let state = AppState::Unlocked { path: path.clone() };
    let busy = state
        .clone()
        .enter_busy()
        .expect("Unlocked transitions to UnlockedBusy");
    assert!(matches!(busy, AppState::UnlockedBusy { .. }));
    assert_path_eq(&busy, &path);
}

#[test]
fn unlocked_busy_leaves_busy_and_preserves_path() {
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let idle = busy
        .clone()
        .leave_busy()
        .expect("UnlockedBusy transitions back to Unlocked");
    assert!(matches!(idle, AppState::Unlocked { .. }));
    assert_path_eq(&idle, &path);
}

#[test]
fn non_unlocked_states_do_not_enter_busy() {
    // The plan §"In-flight effect ownership" says only Unlocked
    // hands the (Vault, Store) pair to a worker. Missing, Locked,
    // and StartupError have no vault to take, and UnlockedBusy
    // is already busy.
    let path = vault_path();
    assert!(AppState::Missing { path: path.clone() }
        .enter_busy()
        .is_none());
    assert!(AppState::Locked { path: path.clone() }
        .enter_busy()
        .is_none());
    assert!(AppState::UnlockedBusy { path: path.clone() }
        .enter_busy()
        .is_none());
    let startup = decide_state_from_inspect(&path, Err(invalid_header_err()))
        .expect("inspect Err yields StartupError state");
    assert!(startup.enter_busy().is_none());
}

#[test]
fn non_busy_states_do_not_leave_busy() {
    let path = vault_path();
    assert!(AppState::Missing { path: path.clone() }
        .leave_busy()
        .is_none());
    assert!(AppState::Locked { path: path.clone() }
        .leave_busy()
        .is_none());
    assert!(AppState::Unlocked { path: path.clone() }
        .leave_busy()
        .is_none());
}

#[test]
fn locked_enters_unlocking_busy_and_preserves_path() {
    // The `gio::spawn_blocking paladin_core::open` worker takes the
    // submitted `VaultLock` from the live `UnlockDialogComponent`
    // and runs Argon2 + AEAD decryption off the main loop. Per
    // `IMPLEMENTATION_PLAN_04_GTK.md` §"Vault interaction", the
    // model transitions `AppState::Locked → AppState::UnlockedBusy`
    // for the worker's lifetime so the busy gating in
    // `is_busy()` / `allows_mutating_menu()` covers the open path
    // alongside the post-unlock mutation path.
    let path = vault_path();
    let locked = AppState::Locked { path: path.clone() };
    let busy = locked
        .clone()
        .enter_unlocking_busy()
        .expect("Locked transitions to UnlockedBusy when open worker takes the VaultLock");
    assert!(matches!(busy, AppState::UnlockedBusy { .. }));
    assert_path_eq(&busy, &path);
}

#[test]
fn non_locked_states_do_not_enter_unlocking_busy() {
    // The unlock-busy entry transition is the symmetric partner of
    // `enter_busy`. `enter_busy` covers `Unlocked → UnlockedBusy`
    // for vault-touching mutations that take the live
    // `(Vault, Store)` pair; this method covers `Locked → UnlockedBusy`
    // for the open worker that is about to compute the pair. Every
    // other state — `Missing` (no encrypted vault to open),
    // `Unlocked` (`enter_busy` already owns that source),
    // `UnlockedBusy` (already serializes through one worker per
    // §"In-flight effect ownership"), and `StartupError` (non-
    // mutating surface) — has no `VaultLock` to hand off, so the
    // transition must refuse.
    let path = vault_path();
    assert!(AppState::Missing { path: path.clone() }
        .enter_unlocking_busy()
        .is_none());
    assert!(AppState::Unlocked { path: path.clone() }
        .enter_unlocking_busy()
        .is_none());
    assert!(AppState::UnlockedBusy { path: path.clone() }
        .enter_unlocking_busy()
        .is_none());
    let startup = decide_state_from_inspect(&path, Err(invalid_header_err()))
        .expect("inspect Err yields StartupError state");
    assert!(startup.enter_unlocking_busy().is_none());
}

#[test]
fn enter_busy_and_enter_unlocking_busy_partition_idle_source_states() {
    // Cross-check: the two busy-entry transitions cover disjoint
    // source states. `Unlocked` (vault is live, worker takes the
    // pair) goes through `enter_busy`; `Locked` (vault is
    // encrypted, worker is about to build the pair) goes through
    // `enter_unlocking_busy`. Neither method should accept the
    // source state the other one owns. Pinned here so a future
    // refactor that widened either method to also accept the other
    // source — collapsing the two typed transitions into a single
    // catch-all — would fail the partition assertion and force an
    // explicit decision.
    let path = vault_path();

    let unlocked = AppState::Unlocked { path: path.clone() };
    assert!(
        unlocked.clone().enter_busy().is_some(),
        "Unlocked must enter busy via enter_busy",
    );
    assert!(
        unlocked.enter_unlocking_busy().is_none(),
        "Unlocked must not enter busy via enter_unlocking_busy — enter_busy already owns this source",
    );

    let locked = AppState::Locked { path: path.clone() };
    assert!(
        locked.clone().enter_busy().is_none(),
        "Locked must not enter busy via enter_busy — enter_unlocking_busy owns this source",
    );
    assert!(
        locked.enter_unlocking_busy().is_some(),
        "Locked must enter busy via enter_unlocking_busy",
    );
}

#[test]
fn unlocked_busy_leaves_unlocking_busy_to_locked_and_preserves_path() {
    // The `gio::spawn_blocking paladin_core::open` worker can return
    // a typed wrong-passphrase failure (`DecryptFailed`,
    // `InvalidPassphrase`). Per `IMPLEMENTATION_PLAN_04_GTK.md`
    // §"Effect errors", the live `UnlockDialogComponent` stays
    // mounted with the inline error so the user can retype, which
    // means `AppState::UnlockedBusy → AppState::Locked` must release
    // the busy gate so the dialog's passphrase entry becomes
    // interactive again. Symmetric partner of `enter_unlocking_busy`
    // for the failure return path.
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let locked = busy
        .clone()
        .leave_unlocking_busy()
        .expect("UnlockedBusy reverts back to Locked on wrong-passphrase failure");
    assert!(matches!(locked, AppState::Locked { .. }));
    assert_path_eq(&locked, &path);
}

#[test]
fn non_unlocked_busy_states_do_not_leave_unlocking_busy() {
    // Only the busy window opened by `enter_unlocking_busy` can be
    // reverted. `Missing` (no encrypted vault to open), `Locked`
    // (no busy window in flight), `Unlocked` (vault already
    // decrypted), and `StartupError` (non-mutating surface) all
    // have no open unlock worker to roll back, so the reversal must
    // refuse so a stray call cannot clobber another idle state.
    let path = vault_path();
    assert!(AppState::Missing { path: path.clone() }
        .leave_unlocking_busy()
        .is_none());
    assert!(AppState::Locked { path: path.clone() }
        .leave_unlocking_busy()
        .is_none());
    assert!(AppState::Unlocked { path: path.clone() }
        .leave_unlocking_busy()
        .is_none());
    let startup = decide_state_from_inspect(&path, Err(invalid_header_err()))
        .expect("inspect Err yields StartupError state");
    assert!(startup.leave_unlocking_busy().is_none());
}

#[test]
fn leave_busy_and_leave_unlocking_busy_share_source_but_diverge_on_destination() {
    // Cross-check: both `leave_busy` and `leave_unlocking_busy`
    // consume the same `UnlockedBusy` source (the busy window
    // opened by either `enter_busy` or `enter_unlocking_busy`), but
    // the worker outcome decides which destination is correct:
    //
    // * `leave_busy → Unlocked` — the worker returned the
    //   `(Vault, Store)` pair (successful unlock, or a save-bearing
    //   mutation that completed). `AppModel` reinstalls the pair
    //   onto its sibling slot per §"In-flight effect ownership".
    // * `leave_unlocking_busy → Locked` — the worker returned a
    //   wrong-passphrase failure. The dialog stays mounted with the
    //   inline error and the user retypes without losing the
    //   surface.
    //
    // Pinned here so a future refactor that collapsed the two
    // transitions into a single catch-all — losing the destination
    // distinction — would fail the partition assertion and force an
    // explicit decision.
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };

    let leave_busy_dest = busy
        .clone()
        .leave_busy()
        .expect("leave_busy accepts UnlockedBusy");
    assert!(
        matches!(leave_busy_dest, AppState::Unlocked { .. }),
        "leave_busy must land on Unlocked",
    );
    assert_path_eq(&leave_busy_dest, &path);

    let leave_unlocking_busy_dest = busy
        .leave_unlocking_busy()
        .expect("leave_unlocking_busy accepts UnlockedBusy");
    assert!(
        matches!(leave_unlocking_busy_dest, AppState::Locked { .. }),
        "leave_unlocking_busy must land on Locked",
    );
    assert_path_eq(&leave_unlocking_busy_dest, &path);
}

// ---------------------------------------------------------------------------
// AppState transitions: unlock (Locked / Missing → Unlocked) and lock
// (Unlocked → Locked)
// ---------------------------------------------------------------------------

#[test]
fn locked_unlocks_and_preserves_path() {
    let path = vault_path();
    let locked = AppState::Locked { path: path.clone() };
    let unlocked = locked
        .clone()
        .into_unlocked()
        .expect("Locked transitions to Unlocked on successful submit");
    assert!(matches!(unlocked, AppState::Unlocked { .. }));
    assert_path_eq(&unlocked, &path);
}

#[test]
fn missing_unlocks_after_init_completion() {
    // `InitDialog` is the only GTK surface that creates a vault.
    // On successful create the AppModel installs (Vault, Store)
    // and transitions Missing → Unlocked carrying the same path.
    let path = vault_path();
    let missing = AppState::Missing { path: path.clone() };
    let unlocked = missing
        .clone()
        .into_unlocked()
        .expect("Missing transitions to Unlocked on InitDialog completion");
    assert!(matches!(unlocked, AppState::Unlocked { .. }));
    assert_path_eq(&unlocked, &path);
}

#[test]
fn unlocked_locks_for_auto_lock_and_preserves_path() {
    let path = vault_path();
    let unlocked = AppState::Unlocked { path: path.clone() };
    let locked = unlocked
        .clone()
        .into_locked()
        .expect("Unlocked transitions to Locked on auto-lock");
    assert!(matches!(locked, AppState::Locked { .. }));
    assert_path_eq(&locked, &path);
}

#[test]
fn non_lockable_states_do_not_lock() {
    let path = vault_path();
    assert!(AppState::Missing { path: path.clone() }
        .into_locked()
        .is_none());
    assert!(AppState::Locked { path: path.clone() }
        .into_locked()
        .is_none());
    // UnlockedBusy must not lock on its own — the plan §"In-flight
    // effect ownership" requires the deferred lock-after-effect path.
    assert!(AppState::UnlockedBusy { path: path.clone() }
        .into_locked()
        .is_none());
}

#[test]
fn non_unlockable_states_do_not_unlock() {
    let path = vault_path();
    assert!(AppState::Unlocked { path: path.clone() }
        .into_unlocked()
        .is_none());
    assert!(AppState::UnlockedBusy { path: path.clone() }
        .into_unlocked()
        .is_none());
    let startup = decide_state_from_inspect(&path, Err(invalid_header_err()))
        .expect("inspect Err yields StartupError state");
    assert!(startup.into_unlocked().is_none());
}

// ---------------------------------------------------------------------------
// Predicates used for menu / control gating per §"libadwaita usage":
// "+ button and the Import / Export / Passphrase / Preferences entries are
// disabled when AppModel is not in Unlocked (so they are off in Missing /
// Locked / StartupError) and disabled while UnlockedBusy is active"
// ---------------------------------------------------------------------------

#[test]
fn mutating_menu_is_enabled_only_on_unlocked() {
    let path = vault_path();
    assert!(AppState::Unlocked { path: path.clone() }.allows_mutating_menu());
    assert!(!AppState::Missing { path: path.clone() }.allows_mutating_menu());
    assert!(!AppState::Locked { path: path.clone() }.allows_mutating_menu());
    assert!(!AppState::UnlockedBusy { path: path.clone() }.allows_mutating_menu());
    let startup = decide_state_from_inspect(&path, Err(invalid_header_err()))
        .expect("inspect Err yields StartupError state");
    assert!(!startup.allows_mutating_menu());
}

#[test]
fn is_busy_is_true_only_on_unlocked_busy() {
    let path = vault_path();
    assert!(AppState::UnlockedBusy { path: path.clone() }.is_busy());
    assert!(!AppState::Unlocked { path: path.clone() }.is_busy());
    assert!(!AppState::Missing { path: path.clone() }.is_busy());
    assert!(!AppState::Locked { path: path.clone() }.is_busy());
    let startup = decide_state_from_inspect(&path, Err(invalid_header_err()))
        .expect("inspect Err yields StartupError state");
    assert!(!startup.is_busy());
}

#[test]
fn is_unlocked_covers_both_idle_and_busy_branches() {
    // Useful for "the AppModel still holds a (Vault, Store) pair"
    // gating — UnlockedBusy keeps the pair conceptually even though
    // the worker physically owns it during the spawn_blocking hop.
    let path = vault_path();
    assert!(AppState::Unlocked { path: path.clone() }.is_unlocked());
    assert!(AppState::UnlockedBusy { path: path.clone() }.is_unlocked());
    assert!(!AppState::Locked { path: path.clone() }.is_unlocked());
    assert!(!AppState::Missing { path: path.clone() }.is_unlocked());
    let startup = decide_state_from_inspect(&path, Err(invalid_header_err()))
        .expect("inspect Err yields StartupError state");
    assert!(!startup.is_unlocked());
}

// ---------------------------------------------------------------------------
// decide_unlock_failure_action — completes the routing of an unlock-worker
// `paladin_core::open` failure by attaching the resolved vault path that
// `AppModel` owns. `DecryptFailed` / `InvalidPassphrase` stay inline on the
// live UnlockDialogComponent surface (carrying the typed InlineError so
// AppModel can dispatch UnlockDialogMsg::OpenFailedInline directly); every
// other failure transitions to AppState::StartupError tagged
// StartupErrorSource::Open with the path attached.
// ---------------------------------------------------------------------------

#[test]
fn decide_unlock_failure_action_decrypt_failed_routes_to_send_inline_to_dialog() {
    let path = vault_path();
    let err = decrypt_failed_err();
    match decide_unlock_failure_action(&path, &err) {
        UnlockFailureAction::SendInlineToDialog(inline) => {
            assert_eq!(inline.kind, ErrorKind::DecryptFailed);
            assert_eq!(inline.rendered, err.to_string());
        }
        UnlockFailureAction::TransitionToStartup(state) => {
            panic!("DecryptFailed must route to SendInlineToDialog, got TransitionToStartup({state:?})")
        }
    }
}

#[test]
fn decide_unlock_failure_action_invalid_passphrase_routes_to_send_inline_to_dialog() {
    let path = vault_path();
    let err = invalid_passphrase_empty_err();
    match decide_unlock_failure_action(&path, &err) {
        UnlockFailureAction::SendInlineToDialog(inline) => {
            assert_eq!(inline.kind, ErrorKind::InvalidPassphrase);
            assert_eq!(inline.rendered, err.to_string());
        }
        UnlockFailureAction::TransitionToStartup(state) => {
            panic!("InvalidPassphrase must route to SendInlineToDialog, got TransitionToStartup({state:?})")
        }
    }
}

#[test]
fn decide_unlock_failure_action_inline_matches_route_unlock_open_error_projection() {
    // The completion helper must not re-derive the InlineError — it
    // passes through whatever `route_unlock_open_error` produced so
    // a single edit there propagates here for free. Pin the
    // projection equality so future divergence is caught at the test
    // boundary.
    let path = vault_path();
    let err = decrypt_failed_err();
    let routed_inline = match route_unlock_open_error(&err) {
        UnlockOpenRouting::Inline(inline) => inline,
        UnlockOpenRouting::Startup => {
            panic!("route_unlock_open_error must route DecryptFailed to Inline")
        }
    };
    match decide_unlock_failure_action(&path, &err) {
        UnlockFailureAction::SendInlineToDialog(inline) => {
            assert_eq!(inline.kind, routed_inline.kind);
            assert_eq!(inline.rendered, routed_inline.rendered);
        }
        UnlockFailureAction::TransitionToStartup(state) => {
            panic!("expected SendInlineToDialog, got TransitionToStartup({state:?})")
        }
    }
}

#[test]
fn decide_unlock_failure_action_unsafe_permissions_routes_to_transition_to_startup_with_formatter_text(
) {
    let path = vault_path();
    let err = unsafe_perms_err();
    let expected_rendered = format_unsafe_permissions(&err).expect("formatter text");
    match decide_unlock_failure_action(&path, &err) {
        UnlockFailureAction::TransitionToStartup(state) => match state {
            AppState::StartupError {
                path: state_path,
                error,
            } => {
                assert_eq!(state_path.as_deref(), Some(path.as_path()));
                assert_eq!(error.source, StartupErrorSource::Open);
                assert_eq!(error.rendered, expected_rendered);
            }
            other => panic!("expected AppState::StartupError, got {other:?}"),
        },
        UnlockFailureAction::SendInlineToDialog(_) => {
            panic!("unsafe_permissions must transition to StartupError")
        }
    }
}

#[test]
fn decide_unlock_failure_action_wrong_vault_lock_routes_to_transition_to_startup() {
    let path = vault_path();
    let err = wrong_vault_lock_err();
    match decide_unlock_failure_action(&path, &err) {
        UnlockFailureAction::TransitionToStartup(AppState::StartupError {
            path: state_path,
            error,
        }) => {
            assert_eq!(state_path.as_deref(), Some(path.as_path()));
            assert_eq!(error.source, StartupErrorSource::Open);
        }
        other => panic!("wrong_vault_lock must transition to StartupError, got {other:?}"),
    }
}

#[test]
fn decide_unlock_failure_action_invalid_header_routes_to_transition_to_startup() {
    let path = vault_path();
    match decide_unlock_failure_action(&path, &invalid_header_err()) {
        UnlockFailureAction::TransitionToStartup(AppState::StartupError {
            path: state_path,
            error,
        }) => {
            assert_eq!(state_path.as_deref(), Some(path.as_path()));
            assert_eq!(error.source, StartupErrorSource::Open);
        }
        other => panic!("invalid_header must transition to StartupError, got {other:?}"),
    }
}

#[test]
fn decide_unlock_failure_action_invalid_payload_routes_to_transition_to_startup() {
    let path = vault_path();
    match decide_unlock_failure_action(&path, &invalid_payload_err()) {
        UnlockFailureAction::TransitionToStartup(AppState::StartupError {
            path: state_path,
            error,
        }) => {
            assert_eq!(state_path.as_deref(), Some(path.as_path()));
            assert_eq!(error.source, StartupErrorSource::Open);
        }
        other => panic!("invalid_payload must transition to StartupError, got {other:?}"),
    }
}

#[test]
fn decide_unlock_failure_action_unsupported_format_version_routes_to_transition_to_startup() {
    let path = vault_path();
    match decide_unlock_failure_action(&path, &unsupported_format_version_err()) {
        UnlockFailureAction::TransitionToStartup(AppState::StartupError {
            path: state_path,
            error,
        }) => {
            assert_eq!(state_path.as_deref(), Some(path.as_path()));
            assert_eq!(error.source, StartupErrorSource::Open);
        }
        other => {
            panic!("unsupported_format_version must transition to StartupError, got {other:?}")
        }
    }
}

#[test]
fn decide_unlock_failure_action_kdf_params_out_of_bounds_routes_to_transition_to_startup() {
    let path = vault_path();
    match decide_unlock_failure_action(&path, &kdf_oob_err()) {
        UnlockFailureAction::TransitionToStartup(AppState::StartupError {
            path: state_path,
            error,
        }) => {
            assert_eq!(state_path.as_deref(), Some(path.as_path()));
            assert_eq!(error.source, StartupErrorSource::Open);
        }
        other => panic!("kdf_params_out_of_bounds must transition to StartupError, got {other:?}"),
    }
}

#[test]
fn decide_unlock_failure_action_io_error_routes_to_transition_to_startup() {
    let path = vault_path();
    match decide_unlock_failure_action(&path, &io_err()) {
        UnlockFailureAction::TransitionToStartup(AppState::StartupError {
            path: state_path,
            error,
        }) => {
            assert_eq!(state_path.as_deref(), Some(path.as_path()));
            assert_eq!(error.source, StartupErrorSource::Open);
        }
        other => panic!("io_error must transition to StartupError, got {other:?}"),
    }
}

#[test]
fn decide_unlock_failure_action_attaches_caller_provided_path() {
    // `route_unlock_open_error` returns a unit `Startup` variant; the
    // completion helper is the *only* place the resolved vault path
    // gets stitched into the StartupError state. Pin path-passthrough
    // explicitly so a future refactor that drops the `path` argument
    // is caught at the test boundary rather than at the call site.
    let alt = PathBuf::from("/var/lib/paladin/alt-vault.bin");
    match decide_unlock_failure_action(&alt, &invalid_header_err()) {
        UnlockFailureAction::TransitionToStartup(AppState::StartupError {
            path: state_path,
            ..
        }) => {
            assert_eq!(state_path.as_deref(), Some(alt.as_path()));
        }
        other => panic!("expected StartupError carrying the alt path, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// apply_unlock_failure_action — translate the typed
// `UnlockFailureAction` into the concrete `UnlockFailureEffect`
// `AppModel`'s update branch applies (forward a `UnlockDialogMsg`
// to the live dialog, or replace `AppModel.state` with a new
// `AppState`). Pulled out of `AppModel::update` so the per-variant
// decision stays unit-testable without spinning up GTK / libadwaita
// or constructing a real vault file.
// ---------------------------------------------------------------------------

#[test]
fn apply_unlock_failure_action_send_inline_to_dialog_translates_to_send_unlock_dialog_msg() {
    // `SendInlineToDialog(inline)` becomes
    // `SendUnlockDialogMsg(UnlockDialogMsg::OpenFailedInline(inline))`
    // — the carried `InlineError` survives the translation byte-
    // identical so the dialog renders the same projection
    // `decide_unlock_failure_action` chose.
    let inline = InlineError::from_error(&PaladinError::DecryptFailed);
    let action = UnlockFailureAction::SendInlineToDialog(inline.clone());
    match apply_unlock_failure_action(action) {
        UnlockFailureEffect::SendUnlockDialogMsg(UnlockDialogMsg::OpenFailedInline(staged)) => {
            assert_eq!(staged.kind, inline.kind);
            assert_eq!(staged.rendered, inline.rendered);
        }
        other => panic!("expected SendUnlockDialogMsg(OpenFailedInline), got {other:?}"),
    }
}

#[test]
fn apply_unlock_failure_action_send_inline_invalid_passphrase_preserves_kind_and_text() {
    // Mirrors the second `UnlockOpenRouting::Inline` source: the
    // pre-KDF `invalid_passphrase` rejection from `paladin_core::open`
    // routes through with its stable §5 `reason` discriminator and
    // `Display` text preserved.
    let err = PaladinError::InvalidPassphrase {
        reason: "zero_length",
    };
    let inline = InlineError::from_error(&err);
    let action = UnlockFailureAction::SendInlineToDialog(inline.clone());
    match apply_unlock_failure_action(action) {
        UnlockFailureEffect::SendUnlockDialogMsg(UnlockDialogMsg::OpenFailedInline(staged)) => {
            assert_eq!(staged.kind, ErrorKind::InvalidPassphrase);
            assert_eq!(staged.rendered, err.to_string());
            assert_eq!(staged.rendered, inline.rendered);
        }
        other => panic!("expected SendUnlockDialogMsg(OpenFailedInline), got {other:?}"),
    }
}

#[test]
fn apply_unlock_failure_action_transition_to_startup_translates_to_set_app_state() {
    // `TransitionToStartup(state)` becomes `SetAppState(state)`
    // verbatim — the carried `AppState::StartupError` (with the
    // resolved path attached and the typed projection populated)
    // survives the translation so `AppModel` installs exactly what
    // `decide_unlock_failure_action` chose.
    let path = vault_path();
    let action = decide_unlock_failure_action(&path, &invalid_header_err());
    match apply_unlock_failure_action(action) {
        UnlockFailureEffect::SetAppState(AppState::StartupError {
            path: state_path,
            error,
        }) => {
            assert_eq!(state_path.as_deref(), Some(path.as_path()));
            assert_eq!(error.source, StartupErrorSource::Open);
        }
        other => panic!("expected SetAppState(StartupError), got {other:?}"),
    }
}

#[test]
fn apply_unlock_failure_action_round_trip_decrypt_failed_dispatches_inline() {
    // End-to-end through both helpers: `decide_unlock_failure_action`
    // routes `DecryptFailed` to `SendInlineToDialog(inline)`;
    // `apply_unlock_failure_action` translates that into a
    // `SendUnlockDialogMsg(UnlockDialogMsg::OpenFailedInline(inline))`.
    // The staged inline projection carries the `decrypt_failed`
    // discriminator and matches `PaladinError::DecryptFailed`'s
    // `Display` text so the dialog label renders the §5 contract.
    let path = vault_path();
    let err = PaladinError::DecryptFailed;
    let action = decide_unlock_failure_action(&path, &err);
    match apply_unlock_failure_action(action) {
        UnlockFailureEffect::SendUnlockDialogMsg(UnlockDialogMsg::OpenFailedInline(inline)) => {
            assert_eq!(inline.kind, ErrorKind::DecryptFailed);
            assert_eq!(inline.rendered, err.to_string());
        }
        other => panic!("expected SendUnlockDialogMsg(OpenFailedInline), got {other:?}"),
    }
}

#[test]
fn apply_unlock_failure_action_round_trip_unsafe_permissions_installs_startup_error() {
    // End-to-end through both helpers: `decide_unlock_failure_action`
    // routes `UnsafePermissions` to
    // `TransitionToStartup(AppState::StartupError { path, error })`;
    // `apply_unlock_failure_action` translates that into a
    // `SetAppState(...)` that `AppModel` installs verbatim.
    let path = vault_path();
    let err = unsafe_perms_err();
    let action = decide_unlock_failure_action(&path, &err);
    match apply_unlock_failure_action(action) {
        UnlockFailureEffect::SetAppState(AppState::StartupError {
            path: state_path,
            error,
        }) => {
            assert_eq!(state_path.as_deref(), Some(path.as_path()));
            assert_eq!(error.source, StartupErrorSource::Open);
        }
        other => panic!("expected SetAppState(StartupError), got {other:?}"),
    }
}

#[test]
fn apply_unlock_failure_action_round_trip_io_error_installs_startup_error() {
    // Pin the IO-error variant explicitly: `route_unlock_open_error`
    // routes every non-passphrase variant to `Startup`, but the §5
    // catalog contract is enforced at this boundary too — a future
    // refactor that adds a fourth `UnlockOpenRouting` variant must
    // either route through `apply_unlock_failure_action` or fail this
    // test.
    let path = vault_path();
    let err = io_err();
    let action = decide_unlock_failure_action(&path, &err);
    match apply_unlock_failure_action(action) {
        UnlockFailureEffect::SetAppState(AppState::StartupError {
            path: state_path,
            error,
        }) => {
            assert_eq!(state_path.as_deref(), Some(path.as_path()));
            assert_eq!(error.source, StartupErrorSource::Open);
        }
        other => panic!("expected SetAppState(StartupError), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// route_unlock_failure_effect — single-shot entry point that composes
// `decide_unlock_failure_action` + `apply_unlock_failure_action` so
// `AppModel`'s future worker-error branch can go from a typed
// `PaladinError` to the concrete `UnlockFailureEffect` in one call
// without bubbling the intermediate `UnlockFailureAction` through the
// update path. Tests pin the composition contract: every
// `route_unlock_failure_effect(path, err)` result must match
// `apply_unlock_failure_action(decide_unlock_failure_action(path,
// err))` byte-for-byte, so a future refactor that drops either
// intermediate helper is caught here.
// ---------------------------------------------------------------------------

#[test]
fn route_unlock_failure_effect_decrypt_failed_dispatches_inline_open_failed() {
    // `DecryptFailed` is the dominant wrong-passphrase outcome
    // (Argon2 succeeds, AEAD authentication fails). The composed
    // router must surface `SendUnlockDialogMsg(OpenFailedInline(_))`
    // carrying the rendered §5 `decrypt_failed` projection so the
    // dialog can flip the inline error label without re-routing the
    // typed `PaladinError`.
    let path = vault_path();
    let err = decrypt_failed_err();
    match route_unlock_failure_effect(&path, &err) {
        UnlockFailureEffect::SendUnlockDialogMsg(UnlockDialogMsg::OpenFailedInline(inline)) => {
            assert_eq!(inline.kind, ErrorKind::DecryptFailed);
            assert_eq!(inline.rendered, err.to_string());
        }
        other => panic!("expected SendUnlockDialogMsg(OpenFailedInline), got {other:?}"),
    }
}

#[test]
fn route_unlock_failure_effect_invalid_passphrase_dispatches_inline_open_failed() {
    // `InvalidPassphrase` covers the pre-KDF rejection path
    // (`zero_length` discriminator). The composed router preserves
    // the kind / rendered text so the dialog renders the §5
    // `invalid_passphrase` line verbatim.
    let path = vault_path();
    let err = invalid_passphrase_empty_err();
    match route_unlock_failure_effect(&path, &err) {
        UnlockFailureEffect::SendUnlockDialogMsg(UnlockDialogMsg::OpenFailedInline(inline)) => {
            assert_eq!(inline.kind, ErrorKind::InvalidPassphrase);
            assert_eq!(inline.rendered, err.to_string());
        }
        other => panic!("expected SendUnlockDialogMsg(OpenFailedInline), got {other:?}"),
    }
}

#[test]
fn route_unlock_failure_effect_unsafe_permissions_sets_startup_state_with_path() {
    // `UnsafePermissions` is the canonical non-passphrase open
    // failure that includes the locked-down `format_unsafe_permissions`
    // rendering. The composed router must build the full
    // `AppState::StartupError { path: Some(path), .. }` so `AppModel`
    // can install it verbatim without re-attaching the path.
    let path = vault_path();
    let err = unsafe_perms_err();
    match route_unlock_failure_effect(&path, &err) {
        UnlockFailureEffect::SetAppState(AppState::StartupError {
            path: state_path,
            error,
        }) => {
            assert_eq!(state_path.as_deref(), Some(path.as_path()));
            assert_eq!(error.source, StartupErrorSource::Open);
            assert_eq!(
                error.rendered,
                format_unsafe_permissions(&err).expect("UnsafePermissions has formatter text")
            );
        }
        other => panic!("expected SetAppState(StartupError), got {other:?}"),
    }
}

#[test]
fn route_unlock_failure_effect_wrong_vault_lock_sets_startup_state() {
    let path = vault_path();
    match route_unlock_failure_effect(&path, &wrong_vault_lock_err()) {
        UnlockFailureEffect::SetAppState(AppState::StartupError {
            path: state_path,
            error,
        }) => {
            assert_eq!(state_path.as_deref(), Some(path.as_path()));
            assert_eq!(error.source, StartupErrorSource::Open);
        }
        other => panic!("expected SetAppState(StartupError), got {other:?}"),
    }
}

#[test]
fn route_unlock_failure_effect_invalid_header_sets_startup_state() {
    let path = vault_path();
    match route_unlock_failure_effect(&path, &invalid_header_err()) {
        UnlockFailureEffect::SetAppState(AppState::StartupError {
            path: state_path,
            error,
        }) => {
            assert_eq!(state_path.as_deref(), Some(path.as_path()));
            assert_eq!(error.source, StartupErrorSource::Open);
        }
        other => panic!("expected SetAppState(StartupError), got {other:?}"),
    }
}

#[test]
fn route_unlock_failure_effect_invalid_payload_sets_startup_state() {
    let path = vault_path();
    match route_unlock_failure_effect(&path, &invalid_payload_err()) {
        UnlockFailureEffect::SetAppState(AppState::StartupError {
            path: state_path,
            error,
        }) => {
            assert_eq!(state_path.as_deref(), Some(path.as_path()));
            assert_eq!(error.source, StartupErrorSource::Open);
        }
        other => panic!("expected SetAppState(StartupError), got {other:?}"),
    }
}

#[test]
fn route_unlock_failure_effect_unsupported_format_version_sets_startup_state() {
    let path = vault_path();
    match route_unlock_failure_effect(&path, &unsupported_format_version_err()) {
        UnlockFailureEffect::SetAppState(AppState::StartupError {
            path: state_path,
            error,
        }) => {
            assert_eq!(state_path.as_deref(), Some(path.as_path()));
            assert_eq!(error.source, StartupErrorSource::Open);
        }
        other => panic!("expected SetAppState(StartupError), got {other:?}"),
    }
}

#[test]
fn route_unlock_failure_effect_kdf_params_out_of_bounds_sets_startup_state() {
    let path = vault_path();
    match route_unlock_failure_effect(&path, &kdf_oob_err()) {
        UnlockFailureEffect::SetAppState(AppState::StartupError {
            path: state_path,
            error,
        }) => {
            assert_eq!(state_path.as_deref(), Some(path.as_path()));
            assert_eq!(error.source, StartupErrorSource::Open);
        }
        other => panic!("expected SetAppState(StartupError), got {other:?}"),
    }
}

#[test]
fn route_unlock_failure_effect_io_error_sets_startup_state() {
    let path = vault_path();
    match route_unlock_failure_effect(&path, &io_err()) {
        UnlockFailureEffect::SetAppState(AppState::StartupError {
            path: state_path,
            error,
        }) => {
            assert_eq!(state_path.as_deref(), Some(path.as_path()));
            assert_eq!(error.source, StartupErrorSource::Open);
        }
        other => panic!("expected SetAppState(StartupError), got {other:?}"),
    }
}

#[test]
fn route_unlock_failure_effect_attaches_caller_provided_path() {
    // The composed router is the *only* boundary that joins the
    // caller-owned vault path to the typed `StartupError` projection
    // on the non-passphrase branch. A future refactor that drops the
    // `path` argument must fail this test rather than silently
    // produce `path: None`.
    let alt = PathBuf::from("/var/lib/paladin/alt-vault.bin");
    match route_unlock_failure_effect(&alt, &invalid_header_err()) {
        UnlockFailureEffect::SetAppState(AppState::StartupError {
            path: state_path, ..
        }) => {
            assert_eq!(state_path.as_deref(), Some(alt.as_path()));
        }
        other => panic!("expected SetAppState(StartupError) with alt path, got {other:?}"),
    }
}

#[test]
fn route_unlock_failure_effect_matches_decide_then_apply_for_inline_branch() {
    // Pin the composition contract: every `route_unlock_failure_effect`
    // result on the inline branch must equal
    // `apply_unlock_failure_action(decide_unlock_failure_action(...))`
    // up to the carried `InlineError`'s observable fields.
    let path = vault_path();
    let err = decrypt_failed_err();
    let composed = route_unlock_failure_effect(&path, &err);
    let stepwise = apply_unlock_failure_action(decide_unlock_failure_action(&path, &err));
    match (composed, stepwise) {
        (
            UnlockFailureEffect::SendUnlockDialogMsg(UnlockDialogMsg::OpenFailedInline(a)),
            UnlockFailureEffect::SendUnlockDialogMsg(UnlockDialogMsg::OpenFailedInline(b)),
        ) => {
            assert_eq!(a.kind, b.kind);
            assert_eq!(a.rendered, b.rendered);
        }
        (composed, stepwise) => panic!(
            "expected matching SendUnlockDialogMsg(OpenFailedInline) on both sides, got composed={composed:?}, stepwise={stepwise:?}"
        ),
    }
}

#[test]
fn route_unlock_failure_effect_matches_decide_then_apply_for_startup_branch() {
    // Pin the composition contract on the non-passphrase branch:
    // both arms must surface the same `AppState::StartupError`
    // (path attached, `StartupErrorSource::Open` tagged).
    let path = vault_path();
    let err = unsafe_perms_err();
    let composed = route_unlock_failure_effect(&path, &err);
    let stepwise = apply_unlock_failure_action(decide_unlock_failure_action(&path, &err));
    match (composed, stepwise) {
        (
            UnlockFailureEffect::SetAppState(AppState::StartupError {
                path: composed_path,
                error: composed_err,
            }),
            UnlockFailureEffect::SetAppState(AppState::StartupError {
                path: stepwise_path,
                error: stepwise_err,
            }),
        ) => {
            assert_eq!(composed_path, stepwise_path);
            assert_eq!(composed_err.source, stepwise_err.source);
            assert_eq!(composed_err.rendered, stepwise_err.rendered);
        }
        (composed, stepwise) => panic!(
            "expected matching SetAppState(StartupError) on both sides, got composed={composed:?}, stepwise={stepwise:?}"
        ),
    }
}

#[test]
fn decide_unlock_success_state_returns_unlocked_variant() {
    // Mirror of `decide_unlock_failure_action` on the success branch:
    // `AppModel`'s future `gio::spawn_blocking paladin_core::open`
    // worker calls this when the worker returns `Ok((Vault, Store))`
    // so the state-machine transition stays pinned by a pure-logic
    // test even though the live `(Vault, Store)` pair is installed
    // separately into `AppModel.vault`.
    let path = vault_path();
    let state = decide_unlock_success_state(&path);
    assert!(
        matches!(state, AppState::Unlocked { .. }),
        "expected AppState::Unlocked, got {state:?}",
    );
}

#[test]
fn decide_unlock_success_state_preserves_resolved_path() {
    // The vault path resolved at startup (or supplied via `--vault`)
    // is owned by `AppModel`; the helper must thread it verbatim
    // into the new `Unlocked` state so the active surface
    // (`AccountListComponent`) can pass it back to subsequent vault
    // effects.
    let path = vault_path();
    let state = decide_unlock_success_state(&path);
    match state {
        AppState::Unlocked { path: state_path } => {
            assert_eq!(state_path, path);
        }
        other => panic!("expected AppState::Unlocked, got {other:?}"),
    }
}

#[test]
fn decide_unlock_success_state_attaches_caller_provided_path() {
    // Pin that the helper does not capture a static / default path:
    // a future refactor that drops the `path` argument must fail
    // this test rather than silently produce the wrong path.
    let alt = PathBuf::from("/var/lib/paladin/alt-vault.bin");
    let state = decide_unlock_success_state(&alt);
    match state {
        AppState::Unlocked { path: state_path } => {
            assert_eq!(state_path, alt);
        }
        other => panic!("expected AppState::Unlocked with alt path, got {other:?}"),
    }
}

#[test]
fn decide_unlock_success_state_does_not_produce_busy_or_other_states() {
    // The unlock worker leaves `AppState::Locked` for `Unlocked`
    // directly (no `UnlockedBusy` intermediate — the worker is
    // producing the `(Vault, Store)` pair, not consuming one).
    // Pin the contract so a future refactor that wires through
    // `UnlockedBusy` must fail this test rather than silently
    // strand the dialog mid-busy.
    let path = vault_path();
    let state = decide_unlock_success_state(&path);
    assert!(
        !matches!(state, AppState::UnlockedBusy { .. }),
        "expected AppState::Unlocked, not UnlockedBusy: {state:?}",
    );
    assert!(
        !matches!(state, AppState::Locked { .. }),
        "expected AppState::Unlocked, not Locked: {state:?}",
    );
    assert!(
        !matches!(state, AppState::Missing { .. }),
        "expected AppState::Unlocked, not Missing: {state:?}",
    );
    assert!(
        !matches!(state, AppState::StartupError { .. }),
        "expected AppState::Unlocked, not StartupError: {state:?}",
    );
}

#[test]
fn decide_unlock_success_state_path_query_returns_supplied_path() {
    // Cross-check through the [`AppState::path`] projection so the
    // accessor downstream surfaces use sees the same path the helper
    // received. `AppModel` will pass the returned state path to the
    // `AccountListComponent` mount and to subsequent vault effects.
    let path = vault_path();
    let state = decide_unlock_success_state(&path);
    assert_eq!(state.path(), Some(path.as_path()));
}

#[test]
fn decide_unlock_success_state_reports_unlocked_predicate() {
    // `AppState::is_unlocked` returns `true` for `Unlocked` /
    // `UnlockedBusy` only. Pin that the success transition flips
    // the predicate on so menu / header-bar gating sites that key
    // off `is_unlocked` see the unlocked surface immediately.
    let path = vault_path();
    let state = decide_unlock_success_state(&path);
    assert!(
        state.is_unlocked(),
        "expected AppState::Unlocked to report is_unlocked == true, got {state:?}",
    );
    assert!(
        !state.is_busy(),
        "expected AppState::Unlocked to report is_busy == false, got {state:?}",
    );
}

#[test]
fn route_unlock_success_effect_returns_set_app_state_unlocked() {
    // Mirror of `route_unlock_failure_effect` on the success branch:
    // `AppModel`'s future `gio::spawn_blocking paladin_core::open`
    // worker calls this when the worker returns `Ok((Vault, Store))`
    // so the typed effect `AppModel::update` applies stays pinned by
    // a pure-logic test even though the live `(Vault, Store)` pair
    // is installed separately into `AppModel.vault`.
    let path = vault_path();
    let UnlockSuccessEffect::SetAppState(state) = route_unlock_success_effect(&path);
    match state {
        AppState::Unlocked { path: state_path } => {
            assert_eq!(state_path, path);
        }
        other => panic!("expected AppState::Unlocked, got {other:?}"),
    }
}

#[test]
fn route_unlock_success_effect_attaches_caller_provided_path() {
    // The composed router is the *only* boundary that joins the
    // caller-owned vault path to the typed `UnlockSuccessEffect` on
    // the success branch. A future refactor that drops the `path`
    // argument must fail this test rather than silently produce the
    // wrong path.
    let alt = PathBuf::from("/var/lib/paladin/alt-vault.bin");
    let UnlockSuccessEffect::SetAppState(state) = route_unlock_success_effect(&alt);
    match state {
        AppState::Unlocked { path: state_path } => {
            assert_eq!(state_path, alt);
        }
        other => panic!("expected AppState::Unlocked with alt path, got {other:?}"),
    }
}

#[test]
fn route_unlock_success_effect_matches_decide_unlock_success_state() {
    // Pin the composition contract: `route_unlock_success_effect`
    // must surface the same `AppState::Unlocked` that
    // `decide_unlock_success_state` returns, wrapped in
    // `UnlockSuccessEffect::SetAppState`. Any future refactor that
    // changes one half of the relationship without the other has to
    // fail this test rather than silently drift the success-branch
    // contract from the failure-branch mirror.
    let path = vault_path();
    let UnlockSuccessEffect::SetAppState(composed) = route_unlock_success_effect(&path);
    let stepwise = decide_unlock_success_state(&path);
    match (composed, stepwise) {
        (
            AppState::Unlocked { path: composed_path },
            AppState::Unlocked { path: stepwise_path },
        ) => {
            assert_eq!(composed_path, stepwise_path);
        }
        (composed, stepwise) => panic!(
            "expected matching AppState::Unlocked on both sides, got composed={composed:?}, stepwise={stepwise:?}"
        ),
    }
}

#[test]
fn route_unlock_success_effect_does_not_produce_other_variants() {
    // The success branch has exactly one effect today —
    // `SetAppState(Unlocked)`. Pin the contract so a future refactor
    // that adds a new variant (drop dialog, mount account list,
    // install `(Vault, Store)`) must explicitly wire the dispatch in
    // `route_unlock_success_effect` rather than silently letting
    // `AppModel::update` keep an `_` catch-all.
    let path = vault_path();
    let effect = route_unlock_success_effect(&path);
    assert!(
        matches!(
            effect,
            UnlockSuccessEffect::SetAppState(AppState::Unlocked { .. })
        ),
        "expected SetAppState(Unlocked), got {effect:?}",
    );
}

// ---------------------------------------------------------------------------
// route_unlock_worker_outcome — unified worker-outcome dispatch
//
// `AppModel::update` calls this from the future `gio::spawn_blocking
// paladin_core::open` worker callback to fan out into the success or
// failure effect with a single entry point, matching the thin-shell
// pattern the rest of `app::state` uses. The two halves stay
// individually testable through `route_unlock_success_effect` /
// `route_unlock_failure_effect`; this composition entry pins the
// success-vs-failure dispatch on the worker `Result`.
// ---------------------------------------------------------------------------

#[test]
fn route_unlock_worker_outcome_ok_returns_success_set_app_state_unlocked() {
    // `Ok(())` represents the `gio::spawn_blocking paladin_core::open`
    // worker returning `Ok((Vault, Store))`. The pair itself is
    // installed separately into `AppModel.vault`; the pure-logic
    // dispatch only owns the state-machine transition, so the unit-
    // tag on the success branch is sufficient to pin the effect.
    let path = vault_path();
    let effect = route_unlock_worker_outcome(&path, Ok(()));
    match effect {
        UnlockWorkerEffect::Success(UnlockSuccessEffect::SetAppState(AppState::Unlocked {
            path: state_path,
        })) => {
            assert_eq!(state_path, path);
        }
        other => panic!("expected Success(SetAppState(Unlocked)), got {other:?}"),
    }
}

#[test]
fn route_unlock_worker_outcome_decrypt_failed_returns_failure_send_unlock_dialog_msg() {
    // Wrong-passphrase failures stay inline on the live
    // `UnlockDialogComponent`. `route_unlock_worker_outcome` must
    // surface the `Failure(SendUnlockDialogMsg(OpenFailedInline(..)))`
    // branch produced by `route_unlock_failure_effect` byte-identical
    // so the typed `InlineError` projection survives the dispatch.
    let path = vault_path();
    let err = decrypt_failed_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    match effect {
        UnlockWorkerEffect::Failure(UnlockFailureEffect::SendUnlockDialogMsg(
            UnlockDialogMsg::OpenFailedInline(inline),
        )) => {
            assert_eq!(inline.kind, ErrorKind::DecryptFailed);
            assert!(
                !inline.rendered.is_empty(),
                "expected non-empty inline rendered text, got empty"
            );
        }
        other => panic!(
            "expected Failure(SendUnlockDialogMsg(OpenFailedInline(..))) for DecryptFailed, got {other:?}"
        ),
    }
}

#[test]
fn route_unlock_worker_outcome_invalid_passphrase_returns_failure_send_unlock_dialog_msg() {
    // Empty-passphrase pre-flight rejections classify as
    // `InvalidPassphrase` once they round-trip through
    // `paladin_core::open`. Same inline-routing rule as
    // `DecryptFailed` — assert both passphrase variants land on the
    // dialog surface so a future drift in
    // `route_unlock_open_error` cannot silently push one to the
    // `StartupError` branch.
    let path = vault_path();
    let err = invalid_passphrase_empty_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    match effect {
        UnlockWorkerEffect::Failure(UnlockFailureEffect::SendUnlockDialogMsg(
            UnlockDialogMsg::OpenFailedInline(inline),
        )) => {
            assert_eq!(inline.kind, ErrorKind::InvalidPassphrase);
        }
        other => panic!(
            "expected Failure(SendUnlockDialogMsg(OpenFailedInline(..))) for InvalidPassphrase, got {other:?}"
        ),
    }
}

#[test]
fn route_unlock_worker_outcome_unsafe_permissions_returns_failure_set_app_state_startup() {
    // Non-passphrase `paladin_core::open` failures drop the live
    // `UnlockDialogComponent` and transition `AppModel` to
    // `StartupError`. `route_unlock_worker_outcome` must surface the
    // `Failure(SetAppState(StartupError { path: Some(_), error: ... }))`
    // branch produced by `route_unlock_failure_effect`, including
    // the formatter-built text per `paladin_core::format_unsafe_permissions`.
    let path = vault_path();
    let err = unsafe_perms_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    match effect {
        UnlockWorkerEffect::Failure(UnlockFailureEffect::SetAppState(AppState::StartupError {
            path: state_path,
            error,
        })) => {
            assert_eq!(state_path.as_deref(), Some(path.as_path()));
            assert_eq!(error.source, StartupErrorSource::Open);
            assert_eq!(
                error.rendered,
                format_unsafe_permissions(&err).expect("UnsafePermissions has formatter text"),
            );
        }
        other => panic!(
            "expected Failure(SetAppState(StartupError {{ source: Open, .. }})), got {other:?}"
        ),
    }
}

#[test]
fn route_unlock_worker_outcome_io_error_returns_failure_set_app_state_startup() {
    // Generic `IoError` is the catch-all branch in
    // `route_unlock_open_error`. Pin it routes to the same
    // `Failure(SetAppState(StartupError))` shape as `UnsafePermissions`
    // so the GUI surface flips off the inline error label and onto
    // the non-mutating `StartupErrorComponent`.
    let path = vault_path();
    let err = io_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    match effect {
        UnlockWorkerEffect::Failure(UnlockFailureEffect::SetAppState(AppState::StartupError {
            path: state_path,
            ..
        })) => {
            assert_eq!(state_path.as_deref(), Some(path.as_path()));
        }
        other => panic!("expected Failure(SetAppState(StartupError)), got {other:?}"),
    }
}

#[test]
fn route_unlock_worker_outcome_ok_matches_route_unlock_success_effect() {
    // Composition contract: the `Ok(())` branch must surface byte-
    // identical to calling `route_unlock_success_effect(path)`
    // directly so a future refactor that drops or changes one helper
    // cannot silently drift the unified dispatch.
    let path = vault_path();
    let unified = route_unlock_worker_outcome(&path, Ok(()));
    let direct = route_unlock_success_effect(&path);
    match (unified, direct) {
        (
            UnlockWorkerEffect::Success(UnlockSuccessEffect::SetAppState(unified_state)),
            UnlockSuccessEffect::SetAppState(direct_state),
        ) => match (unified_state, direct_state) {
            (
                AppState::Unlocked {
                    path: unified_path,
                },
                AppState::Unlocked { path: direct_path },
            ) => {
                assert_eq!(unified_path, direct_path);
            }
            (u, d) => panic!(
                "expected matching AppState::Unlocked on both sides, got unified={u:?}, direct={d:?}"
            ),
        },
        (u, d) => panic!("expected matching Success effects, got unified={u:?}, direct={d:?}"),
    }
}

#[test]
fn route_unlock_worker_outcome_err_decrypt_failed_matches_route_unlock_failure_effect() {
    // Composition contract on the inline-passphrase branch: the
    // `Err(..)` arm must wrap exactly what `route_unlock_failure_effect`
    // returns. The typed `InlineError` projection survives unchanged,
    // including the `kind` and `body` text.
    let path = vault_path();
    let err = decrypt_failed_err();
    let unified = route_unlock_worker_outcome(&path, Err(&err));
    let direct = route_unlock_failure_effect(&path, &err);
    match (unified, direct) {
        (
            UnlockWorkerEffect::Failure(UnlockFailureEffect::SendUnlockDialogMsg(
                UnlockDialogMsg::OpenFailedInline(unified_inline),
            )),
            UnlockFailureEffect::SendUnlockDialogMsg(UnlockDialogMsg::OpenFailedInline(
                direct_inline,
            )),
        ) => {
            assert_eq!(unified_inline.kind, direct_inline.kind);
            assert_eq!(unified_inline.rendered, direct_inline.rendered);
        }
        (u, d) => panic!(
            "expected matching Failure(SendUnlockDialogMsg(OpenFailedInline)), got unified={u:?}, direct={d:?}"
        ),
    }
}

#[test]
fn route_unlock_worker_outcome_err_unsafe_permissions_matches_route_unlock_failure_effect() {
    // Composition contract on the startup-transition branch: the
    // `Err(..)` arm must wrap exactly what `route_unlock_failure_effect`
    // returns, including the path attached by `decide_unlock_failure_action`
    // and the formatter text on the carried `StartupError`.
    let path = vault_path();
    let err = unsafe_perms_err();
    let unified = route_unlock_worker_outcome(&path, Err(&err));
    let direct = route_unlock_failure_effect(&path, &err);
    match (unified, direct) {
        (
            UnlockWorkerEffect::Failure(UnlockFailureEffect::SetAppState(AppState::StartupError {
                path: unified_path,
                error: unified_error,
            })),
            UnlockFailureEffect::SetAppState(AppState::StartupError {
                path: direct_path,
                error: direct_error,
            }),
        ) => {
            assert_eq!(unified_path, direct_path);
            assert_eq!(unified_error.source, direct_error.source);
            assert_eq!(unified_error.rendered, direct_error.rendered);
        }
        (u, d) => panic!(
            "expected matching Failure(SetAppState(StartupError)), got unified={u:?}, direct={d:?}"
        ),
    }
}

#[test]
fn route_unlock_worker_outcome_attaches_caller_provided_path_on_success() {
    // The composed router is the only boundary that joins the caller-
    // owned vault path to the typed `UnlockWorkerEffect` on the
    // success branch. A future refactor that drops the `path`
    // argument must fail this test rather than silently produce the
    // wrong path.
    let alt = PathBuf::from("/var/lib/paladin/alt-vault.bin");
    let effect = route_unlock_worker_outcome(&alt, Ok(()));
    match effect {
        UnlockWorkerEffect::Success(UnlockSuccessEffect::SetAppState(AppState::Unlocked {
            path: state_path,
        })) => {
            assert_eq!(state_path, alt);
        }
        other => panic!("expected Success(SetAppState(Unlocked)) with alt path, got {other:?}"),
    }
}

#[test]
fn route_unlock_worker_outcome_attaches_caller_provided_path_on_startup_failure() {
    // Mirror of the success-branch path-attaching test on the
    // failure-startup branch: `decide_unlock_failure_action` attaches
    // the caller-provided path to the carried `AppState::StartupError`.
    // Pin that the unified router preserves it.
    let alt = PathBuf::from("/var/lib/paladin/alt-vault.bin");
    let err = io_err();
    let effect = route_unlock_worker_outcome(&alt, Err(&err));
    match effect {
        UnlockWorkerEffect::Failure(UnlockFailureEffect::SetAppState(AppState::StartupError {
            path: state_path,
            ..
        })) => {
            assert_eq!(state_path.as_deref(), Some(alt.as_path()));
        }
        other => panic!("expected Failure(SetAppState(StartupError)) with alt path, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// route_unlock_open_completion — bundle worker pair + effect
//
// The `gio::spawn_blocking paladin_core::open` worker returns
// `Result<(Vault, Store), PaladinError>`. Bundling that outcome into a
// single `UnlockWorkerCompletion { effect, pair }` keeps the worker
// closure thin (extract pair on `Ok`, route effect on either branch)
// and lets `AppModel::update` install the pair into the sibling
// `Option<(Vault, Store)>` slot from the same message that drives the
// state transition. The routing rule itself stays delegated to
// `route_unlock_worker_outcome` — this helper is shape-only over the
// worker `Result`.
// ---------------------------------------------------------------------------

#[test]
fn route_unlock_open_completion_ok_carries_pair_and_success_effect() {
    // A successful worker open delivers the live `(Vault, Store)` pair
    // alongside the success-effect transition. The pair must survive
    // the bundling so `AppModel::update` can install it into the
    // sibling `Option<(Vault, Store)>` slot.
    let (_tempdir, path, pair) = fresh_plaintext_vault_pair();

    let completion = paladin_gtk::app::state::route_unlock_open_completion(&path, Ok(pair));

    assert!(
        completion.pair.is_some(),
        "Ok branch must carry the (Vault, Store) pair forward to AppModel",
    );
    match completion.effect {
        UnlockWorkerEffect::Success(UnlockSuccessEffect::SetAppState(AppState::Unlocked {
            path: state_path,
        })) => {
            assert_eq!(state_path, path);
        }
        other => panic!("expected Success(SetAppState(Unlocked)), got {other:?}"),
    }
}

#[test]
fn route_unlock_open_completion_err_decrypt_failed_carries_inline_effect_no_pair() {
    // Wrong-passphrase failures stay inline on the dialog. The
    // completion bundle must report `pair = None` so `AppModel` does
    // not attempt to install a phantom pair, and must surface the
    // typed inline `OpenFailedInline` message verbatim.
    let path = vault_path();
    let err = decrypt_failed_err();

    let completion = paladin_gtk::app::state::route_unlock_open_completion(&path, Err(err));

    assert!(
        completion.pair.is_none(),
        "Err branch must not carry a (Vault, Store) pair",
    );
    match completion.effect {
        UnlockWorkerEffect::Failure(UnlockFailureEffect::SendUnlockDialogMsg(
            UnlockDialogMsg::OpenFailedInline(inline),
        )) => {
            assert_eq!(inline.kind, ErrorKind::DecryptFailed);
            assert!(
                !inline.rendered.is_empty(),
                "expected non-empty inline rendered text, got empty",
            );
        }
        other => panic!(
            "expected Failure(SendUnlockDialogMsg(OpenFailedInline(..))) for DecryptFailed, got {other:?}"
        ),
    }
}

#[test]
fn route_unlock_open_completion_err_invalid_passphrase_carries_inline_effect_no_pair() {
    // Empty-passphrase failures also stay inline. Same bundling
    // contract: `pair = None` and the typed inline message preserved.
    let path = vault_path();
    let err = invalid_passphrase_empty_err();

    let completion = paladin_gtk::app::state::route_unlock_open_completion(&path, Err(err));

    assert!(completion.pair.is_none());
    match completion.effect {
        UnlockWorkerEffect::Failure(UnlockFailureEffect::SendUnlockDialogMsg(
            UnlockDialogMsg::OpenFailedInline(inline),
        )) => {
            assert_eq!(inline.kind, ErrorKind::InvalidPassphrase);
        }
        other => panic!(
            "expected Failure(SendUnlockDialogMsg(OpenFailedInline(..))) for InvalidPassphrase, got {other:?}"
        ),
    }
}

#[test]
fn route_unlock_open_completion_err_unsafe_permissions_carries_startup_effect_no_pair() {
    // Non-passphrase open failures route the app to
    // `StartupErrorComponent`. The bundle must mirror that with
    // `pair = None` and the `StartupError` state carrying the
    // caller-provided path.
    let path = vault_path();
    let err = unsafe_perms_err();

    let completion = paladin_gtk::app::state::route_unlock_open_completion(&path, Err(err));

    assert!(completion.pair.is_none());
    match completion.effect {
        UnlockWorkerEffect::Failure(UnlockFailureEffect::SetAppState(AppState::StartupError {
            path: state_path,
            ..
        })) => {
            assert_eq!(state_path.as_deref(), Some(path.as_path()));
        }
        other => panic!(
            "expected Failure(SetAppState(StartupError)) for UnsafePermissions, got {other:?}"
        ),
    }
}

#[test]
fn route_unlock_open_completion_err_io_error_carries_startup_effect_no_pair() {
    // IoError is the other commonly-hit non-passphrase failure
    // (vault parent dir gone between inspect and open). Same bundling
    // contract as UnsafePermissions.
    let path = vault_path();
    let err = io_err();

    let completion = paladin_gtk::app::state::route_unlock_open_completion(&path, Err(err));

    assert!(completion.pair.is_none());
    match completion.effect {
        UnlockWorkerEffect::Failure(UnlockFailureEffect::SetAppState(AppState::StartupError {
            path: state_path,
            ..
        })) => {
            assert_eq!(state_path.as_deref(), Some(path.as_path()));
        }
        other => panic!("expected Failure(SetAppState(StartupError)) for IoError, got {other:?}"),
    }
}

#[test]
fn route_unlock_open_completion_err_routing_matches_route_unlock_worker_outcome() {
    // The completion helper bundles over `route_unlock_worker_outcome`
    // — the routed effect must match byte-identical so a future
    // refactor cannot silently diverge the two boundaries.
    let path = vault_path();
    for err in [
        decrypt_failed_err(),
        invalid_passphrase_empty_err(),
        unsafe_perms_err(),
        wrong_vault_lock_err(),
        invalid_header_err(),
        invalid_payload_err(),
        unsupported_format_version_err(),
        kdf_oob_err(),
        io_err(),
    ] {
        let direct = route_unlock_worker_outcome(&path, Err(&err));
        let completion = paladin_gtk::app::state::route_unlock_open_completion(&path, Err(err));
        assert_eq!(
            format!("{direct:?}"),
            format!("{:?}", completion.effect),
            "route_unlock_open_completion must produce the same effect as route_unlock_worker_outcome",
        );
    }
}

#[test]
fn route_unlock_open_completion_attaches_caller_provided_path_on_success() {
    // Path attachment must travel through the bundling helper on the
    // success branch so the carried `AppState::Unlocked` reflects the
    // caller-provided path (not the path stored anywhere on the
    // `(Vault, Store)` pair).
    let (_tempdir, _real_path, pair) = fresh_plaintext_vault_pair();
    let alt = PathBuf::from("/var/lib/paladin/alt-vault.bin");

    let completion = paladin_gtk::app::state::route_unlock_open_completion(&alt, Ok(pair));

    match completion.effect {
        UnlockWorkerEffect::Success(UnlockSuccessEffect::SetAppState(AppState::Unlocked {
            path: state_path,
        })) => {
            assert_eq!(state_path, alt);
        }
        other => panic!("expected Success(SetAppState(Unlocked)) with alt path, got {other:?}"),
    }
}

#[test]
fn route_unlock_open_completion_attaches_caller_provided_path_on_failure() {
    // Mirror on the failure-startup branch.
    let alt = PathBuf::from("/var/lib/paladin/alt-vault.bin");
    let err = io_err();

    let completion = paladin_gtk::app::state::route_unlock_open_completion(&alt, Err(err));

    match completion.effect {
        UnlockWorkerEffect::Failure(UnlockFailureEffect::SetAppState(AppState::StartupError {
            path: state_path,
            ..
        })) => {
            assert_eq!(state_path.as_deref(), Some(alt.as_path()));
        }
        other => panic!("expected Failure(SetAppState(StartupError)) with alt path, got {other:?}"),
    }
}

/// Create a fresh plaintext `(Vault, Store)` pair backed by a
/// tempfile vault. The tempdir is chmodded to `0700` so
/// `Store::create` accepts it (§4.3 parent-directory permission
/// check). The tempdir handle is returned so the caller keeps the
/// vault file alive for the duration of the test.
fn fresh_plaintext_vault_pair() -> (
    tempfile::TempDir,
    PathBuf,
    (paladin_core::Vault, paladin_core::Store),
) {
    use std::os::unix::fs::PermissionsExt;

    let tempdir = tempfile::tempdir().expect("create tempdir");
    std::fs::set_permissions(tempdir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod tempdir to 0700 so paladin_core::Store::create accepts it");

    let path = tempdir.path().join("vault.bin");
    let pair = paladin_core::Store::create(&path, paladin_core::VaultInit::Plaintext)
        .expect("create plaintext vault");
    (tempdir, path, pair)
}

// ---------------------------------------------------------------------------
// should_drop_unlock_dialog_after — side-effect dispatch decision
// ---------------------------------------------------------------------------
//
// `AppModel::update` applies an `UnlockWorkerEffect` returned by
// `route_unlock_worker_outcome` by transitioning state and either
// dropping the live `UnlockDialogComponent` controller (success or
// startup-error failure) or keeping it mounted so the user can retype
// (inline passphrase failure). The drop decision is pure-logic — it
// only inspects the typed `UnlockWorkerEffect` shape — so pin it here
// alongside the other unlock-worker dispatch helpers rather than
// re-deriving the rule at every call site.

#[test]
fn should_drop_unlock_dialog_after_success_returns_true() {
    // `UnlockWorkerEffect::Success(SetAppState(Unlocked))` means the
    // worker decrypted the vault. `AppModel::update` follows up by
    // dropping the dialog widget and mounting the
    // `AccountListComponent`, so the helper must report `true`.
    let path = vault_path();
    let effect = route_unlock_worker_outcome(&path, Ok(()));
    assert!(
        paladin_gtk::app::state::should_drop_unlock_dialog_after(&effect),
        "expected success outcome to drop the unlock dialog, got effect={effect:?}",
    );
}

#[test]
fn should_drop_unlock_dialog_after_decrypt_failed_returns_false() {
    // `UnlockWorkerEffect::Failure(SendUnlockDialogMsg(OpenFailedInline))`
    // means the typed passphrase was wrong. `AppModel::update` keeps
    // the dialog mounted and forwards the inline error so the user
    // can retype without losing the dialog surface.
    let path = vault_path();
    let err = decrypt_failed_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    assert!(
        !paladin_gtk::app::state::should_drop_unlock_dialog_after(&effect),
        "expected inline-passphrase failure to keep the unlock dialog mounted, got effect={effect:?}",
    );
}

#[test]
fn should_drop_unlock_dialog_after_invalid_passphrase_returns_false() {
    // Empty-passphrase failure is the second inline-routed error per
    // `route_unlock_open_error`. Pin that it also keeps the dialog
    // mounted so the user can retype — both inline branches share the
    // same dispatch contract.
    let path = vault_path();
    let err = invalid_passphrase_empty_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    assert!(
        !paladin_gtk::app::state::should_drop_unlock_dialog_after(&effect),
        "expected invalid-passphrase failure to keep the unlock dialog mounted, got effect={effect:?}",
    );
}

#[test]
fn should_drop_unlock_dialog_after_unsafe_permissions_returns_true() {
    // `UnlockWorkerEffect::Failure(SetAppState(StartupError))` means
    // the vault file failed a non-passphrase precondition. The dialog
    // gets replaced by the `StartupErrorComponent` surface, so the
    // helper must report `true` to trigger the drop.
    let path = vault_path();
    let err = unsafe_perms_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    assert!(
        paladin_gtk::app::state::should_drop_unlock_dialog_after(&effect),
        "expected unsafe-permissions failure to drop the unlock dialog, got effect={effect:?}",
    );
}

#[test]
fn should_drop_unlock_dialog_after_io_error_returns_true() {
    // Generic IO error is the catch-all startup-routed branch. Pin
    // that it shares the same drop decision as `UnsafePermissions`
    // and every other non-inline failure — the dialog goes away when
    // the GUI flips onto the `StartupErrorComponent` surface.
    let path = vault_path();
    let err = io_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    assert!(
        paladin_gtk::app::state::should_drop_unlock_dialog_after(&effect),
        "expected io-error failure to drop the unlock dialog, got effect={effect:?}",
    );
}

#[test]
fn should_drop_unlock_dialog_after_wrong_vault_lock_returns_true() {
    // `WrongVaultLock` routes to startup-error per the
    // `route_unlock_open_error` table. Pin the dispatch decision for
    // this branch so a future routing refactor that re-classifies
    // this error must explicitly update this test.
    let path = vault_path();
    let err = wrong_vault_lock_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    assert!(
        paladin_gtk::app::state::should_drop_unlock_dialog_after(&effect),
        "expected wrong-vault-lock failure to drop the unlock dialog, got effect={effect:?}",
    );
}

#[test]
fn should_drop_unlock_dialog_after_invalid_header_returns_true() {
    // Cover every typed startup-routed error so the table of "drop on
    // startup-error" branches is pinned exhaustively, not just on
    // representative variants.
    let path = vault_path();
    let err = invalid_header_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    assert!(
        paladin_gtk::app::state::should_drop_unlock_dialog_after(&effect),
        "expected invalid-header failure to drop the unlock dialog, got effect={effect:?}",
    );
}

#[test]
fn should_drop_unlock_dialog_after_invalid_payload_returns_true() {
    let path = vault_path();
    let err = invalid_payload_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    assert!(
        paladin_gtk::app::state::should_drop_unlock_dialog_after(&effect),
        "expected invalid-payload failure to drop the unlock dialog, got effect={effect:?}",
    );
}

#[test]
fn should_drop_unlock_dialog_after_unsupported_format_version_returns_true() {
    let path = vault_path();
    let err = unsupported_format_version_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    assert!(
        paladin_gtk::app::state::should_drop_unlock_dialog_after(&effect),
        "expected unsupported-format-version failure to drop the unlock dialog, got effect={effect:?}",
    );
}

#[test]
fn should_drop_unlock_dialog_after_kdf_params_out_of_bounds_returns_true() {
    let path = vault_path();
    let err = kdf_oob_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    assert!(
        paladin_gtk::app::state::should_drop_unlock_dialog_after(&effect),
        "expected kdf-params-out-of-bounds failure to drop the unlock dialog, got effect={effect:?}",
    );
}

#[test]
fn should_drop_unlock_dialog_after_inspects_effect_only_not_path() {
    // The drop decision is shape-only: it must not depend on the
    // attached path. Two different paths with the same effect shape
    // must produce the same drop decision so a future refactor cannot
    // accidentally introduce path-dependent dialog persistence.
    let path_a = vault_path();
    let path_b = PathBuf::from("/var/lib/paladin/alt-vault.bin");
    let err = decrypt_failed_err();
    let effect_a = route_unlock_worker_outcome(&path_a, Err(&err));
    let effect_b = route_unlock_worker_outcome(&path_b, Err(&err));
    assert_eq!(
        paladin_gtk::app::state::should_drop_unlock_dialog_after(&effect_a),
        paladin_gtk::app::state::should_drop_unlock_dialog_after(&effect_b),
        "drop decision must be shape-only, got differing results for paths {path_a:?} and {path_b:?}",
    );
}

#[test]
fn should_drop_unlock_dialog_after_partitions_inline_vs_non_inline() {
    // Cross-check the partitioning rule: across the full set of
    // worker outcomes, exactly the two inline-passphrase failures
    // keep the dialog mounted; everything else drops it. This guards
    // against a future enum variant being added without updating the
    // dispatch rule.
    let path = vault_path();
    let success = route_unlock_worker_outcome(&path, Ok(()));
    let inline_a = route_unlock_worker_outcome(&path, Err(&decrypt_failed_err()));
    let inline_b = route_unlock_worker_outcome(&path, Err(&invalid_passphrase_empty_err()));
    let startup_a = route_unlock_worker_outcome(&path, Err(&unsafe_perms_err()));
    let startup_b = route_unlock_worker_outcome(&path, Err(&io_err()));

    let drops: Vec<bool> = [&success, &inline_a, &inline_b, &startup_a, &startup_b]
        .iter()
        .map(|effect| paladin_gtk::app::state::should_drop_unlock_dialog_after(effect))
        .collect();

    assert_eq!(
        drops,
        vec![true, false, false, true, true],
        "expected [success, inline_a, inline_b, startup_a, startup_b] = [drop, keep, keep, drop, drop]",
    );
}

// ---------------------------------------------------------------------------
// unlock_dialog_msg_after — inline-dialog-message extraction
// ---------------------------------------------------------------------------
//
// The complement of `should_drop_unlock_dialog_after`: when the
// worker outcome routes through the inline-passphrase branch,
// `AppModel::update` needs the typed `UnlockDialogMsg` to forward to
// the live `UnlockDialogComponent` controller so the user sees the
// wrong-passphrase error without losing the dialog surface. The
// extraction is pure-logic — it only inspects the typed
// `UnlockWorkerEffect` shape — so pin it here alongside the other
// unlock-worker dispatch helpers rather than re-deriving the rule at
// every call site.

#[test]
fn unlock_dialog_msg_after_success_returns_none() {
    // `UnlockWorkerEffect::Success(SetAppState(Unlocked))` means the
    // worker decrypted the vault. There is no inline error to
    // forward — `AppModel::update` drops the dialog instead.
    let path = vault_path();
    let effect = route_unlock_worker_outcome(&path, Ok(()));
    assert!(
        unlock_dialog_msg_after(&effect).is_none(),
        "expected success outcome to carry no dialog message, got {:?}",
        unlock_dialog_msg_after(&effect),
    );
}

#[test]
fn unlock_dialog_msg_after_decrypt_failed_returns_open_failed_inline() {
    // `decrypt_failed` routes through the inline branch per
    // `route_unlock_open_error`. The extracted message must be the
    // `OpenFailedInline` variant carrying an `InlineError` whose
    // `kind` / `rendered` fields match the typed `PaladinError`
    // projection that `InlineError::from_error` would produce.
    let path = vault_path();
    let err = decrypt_failed_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    match unlock_dialog_msg_after(&effect) {
        Some(UnlockDialogMsg::OpenFailedInline(inline)) => {
            assert_eq!(
                inline.kind,
                err.kind(),
                "inline error kind should match the typed PaladinError"
            );
            assert_eq!(
                inline.rendered,
                err.to_string(),
                "inline rendered text should match the typed Display projection"
            );
        }
        other => panic!("expected Some(OpenFailedInline(_)), got {other:?}"),
    }
}

#[test]
fn unlock_dialog_msg_after_invalid_passphrase_returns_open_failed_inline() {
    // Empty-passphrase failure is the second inline-routed branch.
    // Pin that it also surfaces the `OpenFailedInline` message so
    // both inline branches share the same extraction contract.
    let path = vault_path();
    let err = invalid_passphrase_empty_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    match unlock_dialog_msg_after(&effect) {
        Some(UnlockDialogMsg::OpenFailedInline(inline)) => {
            assert_eq!(
                inline.kind,
                err.kind(),
                "inline error kind should match the typed PaladinError"
            );
            assert_eq!(
                inline.rendered,
                err.to_string(),
                "inline rendered text should match the typed Display projection"
            );
        }
        other => panic!("expected Some(OpenFailedInline(_)), got {other:?}"),
    }
}

#[test]
fn unlock_dialog_msg_after_unsafe_permissions_returns_none() {
    // `UnlockWorkerEffect::Failure(SetAppState(StartupError))` means
    // a non-passphrase precondition failed. No inline message is
    // forwarded — the dialog gets dropped in favor of the
    // `StartupErrorComponent` surface.
    let path = vault_path();
    let err = unsafe_perms_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    assert!(
        unlock_dialog_msg_after(&effect).is_none(),
        "expected unsafe-permissions failure to carry no dialog message, got {:?}",
        unlock_dialog_msg_after(&effect),
    );
}

#[test]
fn unlock_dialog_msg_after_io_error_returns_none() {
    // Generic IO error is the catch-all startup-routed branch. Pin
    // that it shares the same "no inline message" extraction as
    // every other non-inline failure.
    let path = vault_path();
    let err = io_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    assert!(
        unlock_dialog_msg_after(&effect).is_none(),
        "expected io-error failure to carry no dialog message, got {:?}",
        unlock_dialog_msg_after(&effect),
    );
}

#[test]
fn unlock_dialog_msg_after_wrong_vault_lock_returns_none() {
    let path = vault_path();
    let err = wrong_vault_lock_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    assert!(
        unlock_dialog_msg_after(&effect).is_none(),
        "expected wrong-vault-lock failure to carry no dialog message, got {:?}",
        unlock_dialog_msg_after(&effect),
    );
}

#[test]
fn unlock_dialog_msg_after_invalid_header_returns_none() {
    let path = vault_path();
    let err = invalid_header_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    assert!(
        unlock_dialog_msg_after(&effect).is_none(),
        "expected invalid-header failure to carry no dialog message, got {:?}",
        unlock_dialog_msg_after(&effect),
    );
}

#[test]
fn unlock_dialog_msg_after_invalid_payload_returns_none() {
    let path = vault_path();
    let err = invalid_payload_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    assert!(
        unlock_dialog_msg_after(&effect).is_none(),
        "expected invalid-payload failure to carry no dialog message, got {:?}",
        unlock_dialog_msg_after(&effect),
    );
}

#[test]
fn unlock_dialog_msg_after_unsupported_format_version_returns_none() {
    let path = vault_path();
    let err = unsupported_format_version_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    assert!(
        unlock_dialog_msg_after(&effect).is_none(),
        "expected unsupported-format-version failure to carry no dialog message, got {:?}",
        unlock_dialog_msg_after(&effect),
    );
}

#[test]
fn unlock_dialog_msg_after_kdf_params_out_of_bounds_returns_none() {
    let path = vault_path();
    let err = kdf_oob_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    assert!(
        unlock_dialog_msg_after(&effect).is_none(),
        "expected kdf-params-out-of-bounds failure to carry no dialog message, got {:?}",
        unlock_dialog_msg_after(&effect),
    );
}

#[test]
fn unlock_dialog_msg_after_inspects_effect_only_not_path() {
    // The extraction is shape-only: it must not depend on the
    // attached path. Two different paths with the same inline-error
    // shape must produce equivalent `OpenFailedInline` projections so
    // a future refactor cannot accidentally introduce path-dependent
    // dialog forwarding.
    let path_a = vault_path();
    let path_b = PathBuf::from("/var/lib/paladin/alt-vault.bin");
    let err = decrypt_failed_err();
    let effect_a = route_unlock_worker_outcome(&path_a, Err(&err));
    let effect_b = route_unlock_worker_outcome(&path_b, Err(&err));
    match (
        unlock_dialog_msg_after(&effect_a),
        unlock_dialog_msg_after(&effect_b),
    ) {
        (
            Some(UnlockDialogMsg::OpenFailedInline(inline_a)),
            Some(UnlockDialogMsg::OpenFailedInline(inline_b)),
        ) => {
            assert_eq!(
                inline_a.kind, inline_b.kind,
                "inline kind must be shape-only, got differing values for paths {path_a:?} and {path_b:?}",
            );
            assert_eq!(
                inline_a.rendered, inline_b.rendered,
                "inline rendered text must be shape-only, got differing values for paths {path_a:?} and {path_b:?}",
            );
        }
        other => panic!("expected both paths to yield Some(OpenFailedInline(_)), got {other:?}"),
    }
}

#[test]
fn unlock_dialog_msg_after_inverts_should_drop_unlock_dialog_after() {
    // Cross-check the partitioning rule: a dialog message is
    // available iff the dialog stays mounted. Equivalently, the drop
    // decision is the inverse of "has inline message". This guards
    // against a future enum variant being added without updating one
    // of the two dispatch helpers in lockstep with the other.
    let path = vault_path();
    let effects = [
        route_unlock_worker_outcome(&path, Ok(())),
        route_unlock_worker_outcome(&path, Err(&decrypt_failed_err())),
        route_unlock_worker_outcome(&path, Err(&invalid_passphrase_empty_err())),
        route_unlock_worker_outcome(&path, Err(&unsafe_perms_err())),
        route_unlock_worker_outcome(&path, Err(&io_err())),
        route_unlock_worker_outcome(&path, Err(&wrong_vault_lock_err())),
        route_unlock_worker_outcome(&path, Err(&invalid_header_err())),
        route_unlock_worker_outcome(&path, Err(&invalid_payload_err())),
        route_unlock_worker_outcome(&path, Err(&unsupported_format_version_err())),
        route_unlock_worker_outcome(&path, Err(&kdf_oob_err())),
    ];
    for effect in &effects {
        let drops = should_drop_unlock_dialog_after(effect);
        let has_msg = unlock_dialog_msg_after(effect).is_some();
        assert_eq!(
            drops, !has_msg,
            "drop decision should be the inverse of having an inline dialog message for effect={effect:?}",
        );
    }
}

// ---------------------------------------------------------------------------
// unlock_app_state_after — `AppState` replacement extraction
// ---------------------------------------------------------------------------
//
// The third leg of the unlock-worker dispatch trio. `AppModel::update`
// needs three things from a `UnlockWorkerEffect`: whether to drop the
// dialog (`should_drop_unlock_dialog_after`), what message to forward
// to the still-mounted dialog (`unlock_dialog_msg_after`), and what
// `AppState` to install in place of `Locked` / `UnlockedBusy`. The
// state-replacement extractor reports `Some(state)` for both
// state-replacing branches (success → `Unlocked`, startup-routed
// failure → `StartupError`) and `None` for the inline-passphrase
// failure (the dialog stays mounted, the state is unchanged). The
// extraction is shape-only — it inspects the typed `UnlockWorkerEffect`
// variant without re-deriving the routing — so the side-effect
// decision in `AppModel::update` stays unit-testable without spinning
// up GTK / libadwaita.

#[test]
fn unlock_app_state_after_success_returns_unlocked_with_path() {
    // `UnlockWorkerEffect::Success(SetAppState(Unlocked))` carries the
    // resolved vault path through the dispatch chain. Pin both the
    // variant shape and the path passthrough so a future refactor
    // cannot silently swap in a stale or empty path.
    let path = vault_path();
    let effect = route_unlock_worker_outcome(&path, Ok(()));
    match unlock_app_state_after(&effect) {
        Some(AppState::Unlocked { path: state_path }) => {
            assert_eq!(state_path, &path);
        }
        other => panic!("expected Some(AppState::Unlocked), got {other:?}"),
    }
}

#[test]
fn unlock_app_state_after_decrypt_failed_returns_none() {
    // Wrong-passphrase failure routes inline — the dialog stays
    // mounted and `AppState` is unchanged. The extractor must report
    // `None` so `AppModel::update` does not clobber the live
    // `Locked` / `UnlockedBusy` state with a phantom transition.
    let path = vault_path();
    let err = decrypt_failed_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    assert!(
        unlock_app_state_after(&effect).is_none(),
        "expected decrypt-failed failure to carry no state replacement, got {:?}",
        unlock_app_state_after(&effect),
    );
}

#[test]
fn unlock_app_state_after_invalid_passphrase_returns_none() {
    // Empty-passphrase failure is the second inline-routed branch.
    // Pin that it also reports `None` so both inline branches share
    // the same extraction contract.
    let path = vault_path();
    let err = invalid_passphrase_empty_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    assert!(
        unlock_app_state_after(&effect).is_none(),
        "expected invalid-passphrase failure to carry no state replacement, got {:?}",
        unlock_app_state_after(&effect),
    );
}

#[test]
fn unlock_app_state_after_unsafe_permissions_returns_startup_error_with_formatter_text() {
    // `UnlockWorkerEffect::Failure(SetAppState(StartupError))` carries
    // the resolved vault path plus a `StartupError` whose `rendered`
    // matches `paladin_core::format_unsafe_permissions`. Pin both the
    // variant shape and the rendered passthrough so a future refactor
    // cannot accidentally desync from the CLI / TUI wording.
    let path = vault_path();
    let err = unsafe_perms_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    match unlock_app_state_after(&effect) {
        Some(AppState::StartupError {
            path: state_path,
            error,
        }) => {
            assert_eq!(state_path.as_deref(), Some(path.as_path()));
            assert_eq!(error.source, StartupErrorSource::Open);
            assert_eq!(
                error.rendered,
                format_unsafe_permissions(&err).expect("UnsafePermissions has formatter text"),
            );
        }
        other => panic!("expected Some(AppState::StartupError), got {other:?}"),
    }
}

#[test]
fn unlock_app_state_after_io_error_returns_startup_error() {
    // Generic IO error is the catch-all startup-routed branch. Pin
    // that it also surfaces a state replacement so every non-inline
    // failure shares the same extraction contract.
    let path = vault_path();
    let err = io_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    match unlock_app_state_after(&effect) {
        Some(AppState::StartupError {
            path: state_path,
            error,
        }) => {
            assert_eq!(state_path.as_deref(), Some(path.as_path()));
            assert_eq!(error.source, StartupErrorSource::Open);
        }
        other => panic!("expected Some(AppState::StartupError), got {other:?}"),
    }
}

#[test]
fn unlock_app_state_after_wrong_vault_lock_returns_startup_error() {
    let path = vault_path();
    let err = wrong_vault_lock_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    match unlock_app_state_after(&effect) {
        Some(AppState::StartupError {
            path: state_path,
            error,
        }) => {
            assert_eq!(state_path.as_deref(), Some(path.as_path()));
            assert_eq!(error.source, StartupErrorSource::Open);
        }
        other => panic!("expected Some(AppState::StartupError), got {other:?}"),
    }
}

#[test]
fn unlock_app_state_after_invalid_header_returns_startup_error() {
    let path = vault_path();
    let err = invalid_header_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    match unlock_app_state_after(&effect) {
        Some(AppState::StartupError {
            path: state_path,
            error,
        }) => {
            assert_eq!(state_path.as_deref(), Some(path.as_path()));
            assert_eq!(error.source, StartupErrorSource::Open);
        }
        other => panic!("expected Some(AppState::StartupError), got {other:?}"),
    }
}

#[test]
fn unlock_app_state_after_invalid_payload_returns_startup_error() {
    let path = vault_path();
    let err = invalid_payload_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    match unlock_app_state_after(&effect) {
        Some(AppState::StartupError {
            path: state_path,
            error,
        }) => {
            assert_eq!(state_path.as_deref(), Some(path.as_path()));
            assert_eq!(error.source, StartupErrorSource::Open);
        }
        other => panic!("expected Some(AppState::StartupError), got {other:?}"),
    }
}

#[test]
fn unlock_app_state_after_unsupported_format_version_returns_startup_error() {
    let path = vault_path();
    let err = unsupported_format_version_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    match unlock_app_state_after(&effect) {
        Some(AppState::StartupError {
            path: state_path,
            error,
        }) => {
            assert_eq!(state_path.as_deref(), Some(path.as_path()));
            assert_eq!(error.source, StartupErrorSource::Open);
        }
        other => panic!("expected Some(AppState::StartupError), got {other:?}"),
    }
}

#[test]
fn unlock_app_state_after_kdf_params_out_of_bounds_returns_startup_error() {
    let path = vault_path();
    let err = kdf_oob_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    match unlock_app_state_after(&effect) {
        Some(AppState::StartupError {
            path: state_path,
            error,
        }) => {
            assert_eq!(state_path.as_deref(), Some(path.as_path()));
            assert_eq!(error.source, StartupErrorSource::Open);
        }
        other => panic!("expected Some(AppState::StartupError), got {other:?}"),
    }
}

#[test]
fn unlock_app_state_after_attaches_caller_provided_path_on_success() {
    // The caller-provided path threads through the dispatch chain on
    // the success branch and lands on the resulting `Unlocked` state.
    // Vary the path independently of the routing decision to pin
    // the passthrough.
    let alt = PathBuf::from("/var/lib/paladin/alt-vault.bin");
    let effect = route_unlock_worker_outcome(&alt, Ok(()));
    match unlock_app_state_after(&effect) {
        Some(AppState::Unlocked { path: state_path }) => {
            assert_eq!(state_path, &alt);
        }
        other => panic!("expected Some(AppState::Unlocked) with alt path, got {other:?}"),
    }
}

#[test]
fn unlock_app_state_after_attaches_caller_provided_path_on_startup_failure() {
    // Same passthrough on the startup-routed failure branch. The
    // `StartupError` carries `Some(alt_path)` so retry can re-run
    // from the same target.
    let alt = PathBuf::from("/var/lib/paladin/alt-vault.bin");
    let err = unsafe_perms_err();
    let effect = route_unlock_worker_outcome(&alt, Err(&err));
    match unlock_app_state_after(&effect) {
        Some(AppState::StartupError {
            path: state_path, ..
        }) => {
            assert_eq!(state_path.as_deref(), Some(alt.as_path()));
        }
        other => panic!("expected Some(AppState::StartupError) with alt path, got {other:?}"),
    }
}

#[test]
fn unlock_app_state_after_inspects_effect_only_not_path() {
    // The presence-or-absence decision is shape-only: it must not
    // depend on the attached path. Two different paths with the same
    // effect shape must produce the same Some/None outcome so a
    // future refactor cannot accidentally introduce path-dependent
    // state replacement.
    let path_a = vault_path();
    let path_b = PathBuf::from("/var/lib/paladin/alt-vault.bin");
    let err = decrypt_failed_err();
    let effect_a = route_unlock_worker_outcome(&path_a, Err(&err));
    let effect_b = route_unlock_worker_outcome(&path_b, Err(&err));
    assert_eq!(
        unlock_app_state_after(&effect_a).is_some(),
        unlock_app_state_after(&effect_b).is_some(),
        "state-replacement presence must be shape-only, got differing results for paths {path_a:?} and {path_b:?}",
    );
}

#[test]
fn unlock_app_state_after_matches_should_drop_unlock_dialog_after() {
    // Cross-check the partitioning rule: a state replacement is
    // available iff the dialog gets dropped. Every state-replacing
    // outcome drops the dialog (success → mount account list;
    // startup-routed failure → mount startup-error component) and
    // every inline outcome keeps it mounted. This guards against a
    // future enum variant being added without updating the two
    // dispatch helpers in lockstep.
    let path = vault_path();
    let effects = [
        route_unlock_worker_outcome(&path, Ok(())),
        route_unlock_worker_outcome(&path, Err(&decrypt_failed_err())),
        route_unlock_worker_outcome(&path, Err(&invalid_passphrase_empty_err())),
        route_unlock_worker_outcome(&path, Err(&unsafe_perms_err())),
        route_unlock_worker_outcome(&path, Err(&io_err())),
        route_unlock_worker_outcome(&path, Err(&wrong_vault_lock_err())),
        route_unlock_worker_outcome(&path, Err(&invalid_header_err())),
        route_unlock_worker_outcome(&path, Err(&invalid_payload_err())),
        route_unlock_worker_outcome(&path, Err(&unsupported_format_version_err())),
        route_unlock_worker_outcome(&path, Err(&kdf_oob_err())),
    ];
    for effect in &effects {
        let drops = should_drop_unlock_dialog_after(effect);
        let has_state = unlock_app_state_after(effect).is_some();
        assert_eq!(
            drops, has_state,
            "drop decision should equal state-replacement presence for effect={effect:?}",
        );
    }
}

#[test]
fn unlock_app_state_after_is_mutually_exclusive_with_unlock_dialog_msg_after() {
    // Cross-check the second partitioning rule: a state replacement
    // and an inline dialog message are mutually exclusive. Every
    // outcome carries either a state replacement, an inline dialog
    // message, or neither — but never both. Guards against a future
    // hybrid variant landing without an explicit dispatch decision.
    let path = vault_path();
    let effects = [
        route_unlock_worker_outcome(&path, Ok(())),
        route_unlock_worker_outcome(&path, Err(&decrypt_failed_err())),
        route_unlock_worker_outcome(&path, Err(&invalid_passphrase_empty_err())),
        route_unlock_worker_outcome(&path, Err(&unsafe_perms_err())),
        route_unlock_worker_outcome(&path, Err(&io_err())),
        route_unlock_worker_outcome(&path, Err(&wrong_vault_lock_err())),
        route_unlock_worker_outcome(&path, Err(&invalid_header_err())),
        route_unlock_worker_outcome(&path, Err(&invalid_payload_err())),
        route_unlock_worker_outcome(&path, Err(&unsupported_format_version_err())),
        route_unlock_worker_outcome(&path, Err(&kdf_oob_err())),
    ];
    for effect in &effects {
        let has_state = unlock_app_state_after(effect).is_some();
        let has_msg = unlock_dialog_msg_after(effect).is_some();
        assert!(
            !(has_state && has_msg),
            "state replacement and inline dialog message must be mutually exclusive for effect={effect:?}",
        );
    }
}

// ---------------------------------------------------------------------------
// unlock_final_app_state — unified state-transition composer
// ---------------------------------------------------------------------------
//
// `unlock_app_state_after` reports the new `AppState` for the two
// state-replacing branches (success → `Unlocked`, startup-routed
// failure → `StartupError`) and `None` for the inline-passphrase
// branch (the dialog stays mounted). The inline branch leaves
// `AppModel` in `AppState::UnlockedBusy` (set by
// `enter_unlocking_busy` before the worker spawned), so
// `AppModel::update` must roll the busy window back to `Locked` via
// `leave_unlocking_busy` to release the busy gate.
//
// `unlock_final_app_state` hides that asymmetry behind a single
// call: it composes `unlock_app_state_after` (replacement cases)
// with `leave_unlocking_busy` (inline rollback case) so callers see
// a uniform `Option<AppState>` regardless of which branch the
// worker outcome took. The `None` return is reserved for the
// defensive case where the inline branch fires but `current` is not
// `UnlockedBusy` — a stray call from an unexpected source state
// that should not silently install a phantom `Locked` transition.

#[test]
fn unlock_final_app_state_success_replaces_with_unlocked_path() {
    // Worker returned `Ok((Vault, Store))`. The trio's
    // `unlock_app_state_after` reports `Some(Unlocked(path))`, so the
    // unified composer must return that same `Unlocked` regardless
    // of `current` — the new state replaces the busy window outright.
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let effect = route_unlock_worker_outcome(&path, Ok(()));
    let next =
        unlock_final_app_state(&busy, &effect).expect("success outcome installs an Unlocked state");
    assert!(matches!(next, AppState::Unlocked { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn unlock_final_app_state_decrypt_failed_rolls_back_to_locked() {
    // Worker returned `Err(DecryptFailed)`. The trio reports `None`
    // (state unchanged), so the unified composer rolls the busy
    // window back via `leave_unlocking_busy` → `Locked(path)`. The
    // dialog stays mounted with its inline error and the user can
    // retype without losing the surface.
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = decrypt_failed_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    let next = unlock_final_app_state(&busy, &effect)
        .expect("inline failure rolls back UnlockedBusy → Locked");
    assert!(matches!(next, AppState::Locked { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn unlock_final_app_state_invalid_passphrase_rolls_back_to_locked() {
    // Second inline-routed branch — empty passphrase. Pin the same
    // rollback so both inline failures share the contract.
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = invalid_passphrase_empty_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    let next = unlock_final_app_state(&busy, &effect)
        .expect("inline failure rolls back UnlockedBusy → Locked");
    assert!(matches!(next, AppState::Locked { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn unlock_final_app_state_unsafe_permissions_replaces_with_startup_error() {
    // Worker returned `Err(UnsafePermissions)`. The trio reports
    // `Some(StartupError(path, ...))`, so the unified composer
    // returns the absolute startup-error state — no rollback needed
    // because the new state replaces outright. The carried
    // `StartupError.rendered` matches `format_unsafe_permissions`
    // per the trio's existing pinning.
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = unsafe_perms_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    let next = unlock_final_app_state(&busy, &effect)
        .expect("startup-routed failure installs a StartupError");
    match next {
        AppState::StartupError {
            path: state_path,
            error,
        } => {
            assert_eq!(state_path.as_deref(), Some(path.as_path()));
            let expected = format_unsafe_permissions(&err)
                .expect("UnsafePermissions has a formatter-provided rendering");
            assert_eq!(error.rendered, expected);
            assert!(matches!(error.source, StartupErrorSource::Open));
        }
        other => panic!("expected AppState::StartupError, got {other:?}"),
    }
}

#[test]
fn unlock_final_app_state_io_error_replaces_with_startup_error() {
    // Non-passphrase, non-UnsafePermissions failure variant.
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = io_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    let next = unlock_final_app_state(&busy, &effect)
        .expect("startup-routed failure installs a StartupError");
    assert!(matches!(next, AppState::StartupError { .. }));
}

#[test]
fn unlock_final_app_state_wrong_vault_lock_replaces_with_startup_error() {
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = wrong_vault_lock_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    let next =
        unlock_final_app_state(&busy, &effect).expect("wrong_vault_lock installs a StartupError");
    assert!(matches!(next, AppState::StartupError { .. }));
}

#[test]
fn unlock_final_app_state_invalid_header_replaces_with_startup_error() {
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = invalid_header_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    let next =
        unlock_final_app_state(&busy, &effect).expect("invalid_header installs a StartupError");
    assert!(matches!(next, AppState::StartupError { .. }));
}

#[test]
fn unlock_final_app_state_invalid_payload_replaces_with_startup_error() {
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = invalid_payload_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    let next =
        unlock_final_app_state(&busy, &effect).expect("invalid_payload installs a StartupError");
    assert!(matches!(next, AppState::StartupError { .. }));
}

#[test]
fn unlock_final_app_state_unsupported_format_version_replaces_with_startup_error() {
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = unsupported_format_version_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    let next = unlock_final_app_state(&busy, &effect)
        .expect("unsupported_format_version installs a StartupError");
    assert!(matches!(next, AppState::StartupError { .. }));
}

#[test]
fn unlock_final_app_state_kdf_params_out_of_bounds_replaces_with_startup_error() {
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = kdf_oob_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    let next = unlock_final_app_state(&busy, &effect)
        .expect("kdf_params_out_of_bounds installs a StartupError");
    assert!(matches!(next, AppState::StartupError { .. }));
}

#[test]
fn unlock_final_app_state_inline_from_non_unlocked_busy_returns_none() {
    // Defensive: the inline branch can only roll back the busy
    // window if `current` is `UnlockedBusy`. A stray call from any
    // other state returns `None` rather than silently installing a
    // phantom `Locked` transition that would replace another idle
    // state. Mirrors the `leave_unlocking_busy` contract pinned by
    // `non_unlocked_busy_states_do_not_leave_unlocking_busy`.
    let path = vault_path();
    let err = decrypt_failed_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    let invalid_sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
        decide_state_from_inspect(&path, Err(invalid_header_err()))
            .expect("inspect Err yields StartupError state"),
    ];
    for source in &invalid_sources {
        assert!(
            unlock_final_app_state(source, &effect).is_none(),
            "inline rollback from {source:?} must refuse to install a phantom Locked",
        );
    }
}

#[test]
fn unlock_final_app_state_replacement_branches_ignore_current_state() {
    // For the two replacement branches (success, startup-routed
    // failure), the new state replaces `current` outright. Pin that
    // the composer returns the same `Some(new_state)` regardless of
    // which source state is passed in — the trio's
    // `unlock_app_state_after` already projects the absolute new
    // state, so `current` is not consulted for replacement.
    let path = vault_path();
    let success_effect = route_unlock_worker_outcome(&path, Ok(()));
    let unsafe_err = unsafe_perms_err();
    let startup_effect = route_unlock_worker_outcome(&path, Err(&unsafe_err));
    let sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
        AppState::UnlockedBusy { path: path.clone() },
    ];
    for source in &sources {
        let next = unlock_final_app_state(source, &success_effect)
            .expect("success replacement ignores current");
        assert!(matches!(next, AppState::Unlocked { .. }));
        let next = unlock_final_app_state(source, &startup_effect)
            .expect("startup replacement ignores current");
        assert!(matches!(next, AppState::StartupError { .. }));
    }
}

#[test]
fn unlock_final_app_state_matches_unlock_app_state_after_on_replacement_branches() {
    // Cross-check: when `unlock_app_state_after` reports
    // `Some(state)`, the composer must return exactly that state.
    // This pins that the composer never re-derives the projection —
    // it only fills in the inline gap with `leave_unlocking_busy`.
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let effects = [
        route_unlock_worker_outcome(&path, Ok(())),
        route_unlock_worker_outcome(&path, Err(&unsafe_perms_err())),
        route_unlock_worker_outcome(&path, Err(&io_err())),
        route_unlock_worker_outcome(&path, Err(&wrong_vault_lock_err())),
        route_unlock_worker_outcome(&path, Err(&invalid_header_err())),
        route_unlock_worker_outcome(&path, Err(&invalid_payload_err())),
        route_unlock_worker_outcome(&path, Err(&unsupported_format_version_err())),
        route_unlock_worker_outcome(&path, Err(&kdf_oob_err())),
    ];
    for effect in &effects {
        let trio_state = unlock_app_state_after(effect)
            .expect("replacement-branch effect carries a state replacement");
        let composer_state = unlock_final_app_state(&busy, effect)
            .expect("replacement-branch composer mirrors the trio");
        assert_eq!(
            std::mem::discriminant(trio_state),
            std::mem::discriminant(&composer_state),
            "composer must mirror the trio's variant for effect={effect:?}",
        );
        assert_eq!(
            trio_state.path().map(Path::to_path_buf),
            composer_state.path().map(Path::to_path_buf),
            "composer must mirror the trio's path for effect={effect:?}",
        );
    }
}

#[test]
fn unlock_final_app_state_inline_branches_roll_back_to_locked_only() {
    // Cross-check: for both inline-routed branches the composer
    // returns exactly `Some(Locked(path))` when `current` is
    // `UnlockedBusy(path)`. Guards against a future enum variant
    // routing through the inline branch with a different rollback
    // target — the rollback rule must stay `UnlockedBusy → Locked`.
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let inline_effects = [
        route_unlock_worker_outcome(&path, Err(&decrypt_failed_err())),
        route_unlock_worker_outcome(&path, Err(&invalid_passphrase_empty_err())),
    ];
    for effect in &inline_effects {
        let next = unlock_final_app_state(&busy, effect)
            .expect("inline failure rolls back UnlockedBusy → Locked");
        assert!(
            matches!(next, AppState::Locked { .. }),
            "inline rollback target must be Locked for effect={effect:?}",
        );
        assert_path_eq(&next, &path);
    }
}

#[test]
fn unlock_final_app_state_some_iff_drop_dialog_or_unlocked_busy_source() {
    // Cross-check: the composer returns `Some` exactly when either
    // (a) the trio drops the dialog (replacement branch — current
    // is ignored) or (b) the trio keeps the dialog mounted but
    // `current` is `UnlockedBusy` (inline branch — `leave_unlocking_busy`
    // accepts). Any other combination returns `None`. This pins the
    // composer's partitioning so a future refactor cannot silently
    // accept an unexpected source state through the inline branch.
    let path = vault_path();
    let sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
        AppState::UnlockedBusy { path: path.clone() },
    ];
    let effects = [
        route_unlock_worker_outcome(&path, Ok(())),
        route_unlock_worker_outcome(&path, Err(&decrypt_failed_err())),
        route_unlock_worker_outcome(&path, Err(&invalid_passphrase_empty_err())),
        route_unlock_worker_outcome(&path, Err(&unsafe_perms_err())),
        route_unlock_worker_outcome(&path, Err(&io_err())),
    ];
    for effect in &effects {
        let drops = should_drop_unlock_dialog_after(effect);
        for source in &sources {
            let is_busy = matches!(source, AppState::UnlockedBusy { .. });
            let expected_some = drops || is_busy;
            let actual_some = unlock_final_app_state(source, effect).is_some();
            assert_eq!(
                expected_some, actual_some,
                "composer must return Some iff drop=true or source is UnlockedBusy; \
                 drop={drops}, is_busy={is_busy}, source={source:?}, effect={effect:?}",
            );
        }
    }
}

// ---------------------------------------------------------------------------
// compose_unlock_dispatch
// ---------------------------------------------------------------------------

#[test]
fn compose_unlock_dispatch_success_bundles_drop_and_unlocked_replacement() {
    // Success outcome: the dialog is dropped, no inline message is
    // forwarded, and `AppModel.state` is replaced with the new
    // `Unlocked(path)` projected by `decide_unlock_success_state`.
    // The composer's three fields must match the existing trio
    // exactly so `AppModel::update` can apply the worker outcome in
    // a single shot without re-routing the effect.
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let effect = route_unlock_worker_outcome(&path, Ok(()));
    let dispatch = compose_unlock_dispatch(&busy, &effect);
    assert!(
        dispatch.drop_dialog,
        "success replacement must drop the UnlockDialog controller",
    );
    assert!(
        dispatch.dialog_msg.is_none(),
        "success replacement must not forward an inline message",
    );
    let next = dispatch
        .app_state
        .expect("success replacement carries a state");
    assert!(
        matches!(next, AppState::Unlocked { .. }),
        "success replacement target must be Unlocked, got {next:?}",
    );
    assert_path_eq(&next, &path);
}

#[test]
fn compose_unlock_dispatch_startup_failure_bundles_drop_and_startup_replacement() {
    // A `unsafe_permissions` open failure routes through the
    // startup-error branch: the dialog drops, no inline message is
    // forwarded, and `AppModel.state` is replaced with the new
    // `StartupError(path)` carrying the routed error. Same one-shot
    // contract as the success branch.
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = unsafe_perms_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    let dispatch = compose_unlock_dispatch(&busy, &effect);
    assert!(
        dispatch.drop_dialog,
        "startup-routed failure must drop the UnlockDialog controller",
    );
    assert!(
        dispatch.dialog_msg.is_none(),
        "startup-routed failure must not forward an inline message",
    );
    let next = dispatch
        .app_state
        .expect("startup-routed failure carries a state");
    assert!(
        matches!(next, AppState::StartupError { .. }),
        "startup-routed failure target must be StartupError, got {next:?}",
    );
    assert_eq!(
        next.path().map(Path::to_path_buf),
        Some(path),
        "startup-routed failure preserves the resolved path",
    );
}

#[test]
fn compose_unlock_dispatch_inline_failure_keeps_dialog_with_msg_and_rolls_back_to_locked() {
    // A `decrypt_failed` open failure routes through the inline
    // branch: the dialog stays mounted (drop_dialog = false), an
    // `OpenFailedInline` message is forwarded to the live dialog
    // controller, and the busy window rolls back from
    // `UnlockedBusy(path)` to `Locked(path)` so the entry row
    // becomes interactive again.
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = decrypt_failed_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    let dispatch = compose_unlock_dispatch(&busy, &effect);
    assert!(
        !dispatch.drop_dialog,
        "inline failure must keep the UnlockDialog controller mounted",
    );
    let msg = dispatch
        .dialog_msg
        .as_ref()
        .expect("inline failure forwards an OpenFailedInline message");
    assert!(
        matches!(msg, UnlockDialogMsg::OpenFailedInline(_)),
        "inline failure must forward OpenFailedInline, got {msg:?}",
    );
    let next = dispatch
        .app_state
        .expect("inline failure rolls back UnlockedBusy → Locked");
    assert!(
        matches!(next, AppState::Locked { .. }),
        "inline rollback target must be Locked, got {next:?}",
    );
    assert_path_eq(&next, &path);
}

#[test]
fn compose_unlock_dispatch_inline_failure_invalid_passphrase_matches_decrypt_failed_shape() {
    // The two inline-routed errors (`decrypt_failed` and
    // `invalid_passphrase`) must share the dispatch shape: dialog
    // stays mounted, an `OpenFailedInline` message is forwarded,
    // and the busy window rolls back to `Locked(path)`. Only the
    // `InlineError` payload inside the message differs — the
    // composer treats them identically.
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = invalid_passphrase_empty_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    let dispatch = compose_unlock_dispatch(&busy, &effect);
    assert!(!dispatch.drop_dialog);
    assert!(matches!(
        dispatch.dialog_msg.as_ref(),
        Some(UnlockDialogMsg::OpenFailedInline(_)),
    ));
    let next = dispatch
        .app_state
        .expect("inline failure rolls back UnlockedBusy → Locked");
    assert!(matches!(next, AppState::Locked { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn compose_unlock_dispatch_mirrors_trio_for_every_effect() {
    // Cross-check: the composer must mirror the existing trio
    // exactly. `drop_dialog`, `dialog_msg`, and `app_state` are the
    // three projections `AppModel::update` would otherwise call
    // separately — bundling them must not change any individual
    // decision. Pins that the composer is a pure aggregator and
    // never re-routes the effect.
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let effects = [
        route_unlock_worker_outcome(&path, Ok(())),
        route_unlock_worker_outcome(&path, Err(&decrypt_failed_err())),
        route_unlock_worker_outcome(&path, Err(&invalid_passphrase_empty_err())),
        route_unlock_worker_outcome(&path, Err(&unsafe_perms_err())),
        route_unlock_worker_outcome(&path, Err(&io_err())),
        route_unlock_worker_outcome(&path, Err(&wrong_vault_lock_err())),
        route_unlock_worker_outcome(&path, Err(&invalid_header_err())),
        route_unlock_worker_outcome(&path, Err(&invalid_payload_err())),
        route_unlock_worker_outcome(&path, Err(&unsupported_format_version_err())),
        route_unlock_worker_outcome(&path, Err(&kdf_oob_err())),
    ];
    for effect in &effects {
        let dispatch = compose_unlock_dispatch(&busy, effect);
        assert_eq!(
            dispatch.drop_dialog,
            should_drop_unlock_dialog_after(effect),
            "drop_dialog must mirror the trio for effect={effect:?}",
        );
        let trio_msg = unlock_dialog_msg_after(effect).cloned();
        match (&dispatch.dialog_msg, &trio_msg) {
            (None, None)
            | (
                Some(UnlockDialogMsg::OpenFailedInline(_)),
                Some(UnlockDialogMsg::OpenFailedInline(_)),
            ) => {}
            other => {
                panic!("dialog_msg must mirror the trio for effect={effect:?}, got {other:?}",)
            }
        }
        let trio_state = unlock_final_app_state(&busy, effect);
        match (&dispatch.app_state, &trio_state) {
            (None, None) => {}
            (Some(a), Some(b)) => {
                assert_eq!(
                    std::mem::discriminant::<AppState>(a),
                    std::mem::discriminant::<AppState>(b),
                    "app_state variant must mirror the trio for effect={effect:?}",
                );
                assert_eq!(
                    a.path().map(Path::to_path_buf),
                    b.path().map(Path::to_path_buf),
                    "app_state path must mirror the trio for effect={effect:?}",
                );
            }
            other => panic!(
                "app_state Some/None must mirror the trio for effect={effect:?}, got {other:?}",
            ),
        }
    }
}

#[test]
fn compose_unlock_dispatch_inline_from_non_unlocked_busy_keeps_dialog_with_no_state() {
    // Defensive: when the worker reports an inline failure but
    // `current` is not `UnlockedBusy` (a stray dispatch from any
    // other source state), the composer must keep the dialog
    // mounted (drop_dialog = false), still forward the inline
    // message, and refuse to install a phantom `Locked` transition
    // (app_state = None). Mirrors the `leave_unlocking_busy`
    // contract pinned by `unlock_final_app_state_inline_from_non_unlocked_busy_returns_none`.
    let path = vault_path();
    let err = decrypt_failed_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    let invalid_sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
    ];
    for source in &invalid_sources {
        let dispatch = compose_unlock_dispatch(source, &effect);
        assert!(
            !dispatch.drop_dialog,
            "inline branch keeps the dialog mounted regardless of source={source:?}",
        );
        assert!(
            matches!(
                dispatch.dialog_msg.as_ref(),
                Some(UnlockDialogMsg::OpenFailedInline(_)),
            ),
            "inline branch forwards OpenFailedInline regardless of source={source:?}",
        );
        assert!(
            dispatch.app_state.is_none(),
            "inline branch must refuse to install a phantom Locked from source={source:?}, \
             got {:?}",
            dispatch.app_state,
        );
    }
}

// ---------------------------------------------------------------------------
// submit_unlock_app_state — pre-worker `Locked → UnlockedBusy` composer
// ---------------------------------------------------------------------------
//
// Symmetric partner of `unlock_final_app_state`: the worker-completion
// composer rolls `UnlockedBusy` back to `Locked` (inline branch) or
// installs `Unlocked` / `StartupError` (replacement branches), while
// `submit_unlock_app_state` covers the *entry* side — the
// `Locked → UnlockedBusy` handoff that `AppModel::update` runs when
// `UnlockDialogOutput::SubmitLock` arrives and the open worker is about
// to spawn. Together the two composers bracket the busy gate so the
// `is_busy()` / `allows_mutating_menu()` gating in `AppState` covers the
// full open worker lifetime per `IMPLEMENTATION_PLAN_04_GTK.md`
// §"Vault interaction".

#[test]
fn submit_unlock_app_state_from_locked_returns_unlocked_busy_preserving_path() {
    // Happy path: `AppModel::update` receives `SubmitLock` while the
    // model is `AppState::Locked(path)`. The composer must hand
    // `AppModel` the `UnlockedBusy(path)` transition that opens the
    // busy gate for the `gio::spawn_blocking paladin_core::open`
    // worker. The resolved path is preserved verbatim so the
    // `UnlockDialogComponent` (kept mounted until the worker
    // completes) still names the same destination.
    let path = vault_path();
    let locked = AppState::Locked { path: path.clone() };
    let next =
        submit_unlock_app_state(&locked).expect("Locked must transition to UnlockedBusy on submit");
    assert!(matches!(next, AppState::UnlockedBusy { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn submit_unlock_app_state_from_non_locked_returns_none() {
    // Defensive: a stray `SubmitLock` dispatch from any source state
    // other than `Locked` is a no-op for the state machine. Missing
    // has no encrypted vault to open, Unlocked / UnlockedBusy already
    // own a different busy window through `enter_busy`, and
    // StartupError is the non-mutating surface. Returning `None`
    // matches `AppState::enter_unlocking_busy`'s own refusal contract
    // so `AppModel::update` leaves the source state in place rather
    // than installing a phantom `UnlockedBusy` that would clobber the
    // idle state.
    let path = vault_path();
    assert!(submit_unlock_app_state(&AppState::Missing { path: path.clone() }).is_none());
    assert!(submit_unlock_app_state(&AppState::Unlocked { path: path.clone() }).is_none());
    assert!(submit_unlock_app_state(&AppState::UnlockedBusy { path: path.clone() }).is_none());
    let startup = decide_state_from_inspect(&path, Err(invalid_header_err()))
        .expect("inspect Err yields StartupError state");
    assert!(submit_unlock_app_state(&startup).is_none());
}

#[test]
fn submit_unlock_app_state_mirrors_enter_unlocking_busy_for_every_variant() {
    // Cross-check: the composer must mirror `AppState::enter_unlocking_busy`
    // exactly — the entry transition is `Locked → UnlockedBusy` for
    // both helpers and `None` for every other source. `submit_unlock_app_state`
    // is a name-the-entry-point wrapper, not a re-derivation; this test pins
    // that contract so the helper can't drift away from
    // `enter_unlocking_busy` without breaking here first.
    let path = vault_path();
    let sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
        AppState::UnlockedBusy { path: path.clone() },
        decide_state_from_inspect(&path, Err(invalid_header_err()))
            .expect("inspect Err yields StartupError state"),
    ];
    for source in &sources {
        let mirror = source.clone().enter_unlocking_busy();
        let composed = submit_unlock_app_state(source);
        match (&mirror, &composed) {
            (None, None) => {}
            (Some(a), Some(b)) => {
                assert_eq!(
                    std::mem::discriminant::<AppState>(a),
                    std::mem::discriminant::<AppState>(b),
                    "composed variant must mirror enter_unlocking_busy for source={source:?}",
                );
                assert_eq!(
                    a.path().map(Path::to_path_buf),
                    b.path().map(Path::to_path_buf),
                    "composed path must mirror enter_unlocking_busy for source={source:?}",
                );
            }
            other => panic!(
                "composed Some/None must mirror enter_unlocking_busy for source={source:?}, \
                 got {other:?}",
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// submit_rename_app_state — pre-worker `Unlocked → UnlockedBusy` composer
// ---------------------------------------------------------------------------
//
// Symmetric partner of `submit_unlock_app_state` for the rename path:
// where `submit_unlock_app_state` covers `Locked → UnlockedBusy` (the
// open worker is computing the `(Vault, Store)` pair),
// `submit_rename_app_state` covers `Unlocked → UnlockedBusy` (the
// rename worker takes the already-decrypted pair through
// `Vault::mutate_and_save`). Both are name-the-entry-point wrappers
// over the matching `AppState` transition method — this one delegates
// to `AppState::enter_busy()`. Together they document each typed
// dispatch's source-state contract at the call site in
// `AppModel::update`. Per `IMPLEMENTATION_PLAN_04_GTK.md`
// §"Vault interaction".

#[test]
fn submit_rename_app_state_from_unlocked_returns_unlocked_busy_preserving_path() {
    // Happy path: `AppModel::update` receives
    // `RenameDialogOutput::SubmitLabel` while the model is
    // `AppState::Unlocked(path)`. The composer must hand `AppModel`
    // the `UnlockedBusy(path)` transition that opens the busy gate
    // for the `gio::spawn_blocking Vault::mutate_and_save(|v|
    // v.rename(...))` worker. The resolved path is preserved
    // verbatim so the rest of `AppModel` (account list, kebab menu,
    // dialog chrome) still names the same vault destination.
    let path = vault_path();
    let unlocked = AppState::Unlocked { path: path.clone() };
    let next = submit_rename_app_state(&unlocked)
        .expect("Unlocked must transition to UnlockedBusy on submit");
    assert!(matches!(next, AppState::UnlockedBusy { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn submit_rename_app_state_from_non_unlocked_returns_none() {
    // Defensive: a stray `SubmitLabel` dispatch from any source
    // state other than `Unlocked` is a no-op for the state machine.
    // Missing / Locked have no live `(Vault, Store)` pair to hand
    // off, `UnlockedBusy` already serializes through one worker per
    // §"In-flight effect ownership", and `StartupError` is the
    // non-mutating surface. Returning `None` matches
    // `AppState::enter_busy`'s own refusal contract so
    // `AppModel::update` leaves the source state in place rather
    // than installing a phantom `UnlockedBusy` that would clobber
    // the idle state.
    let path = vault_path();
    assert!(submit_rename_app_state(&AppState::Missing { path: path.clone() }).is_none());
    assert!(submit_rename_app_state(&AppState::Locked { path: path.clone() }).is_none());
    assert!(submit_rename_app_state(&AppState::UnlockedBusy { path: path.clone() }).is_none());
    let startup = decide_state_from_inspect(&path, Err(invalid_header_err()))
        .expect("inspect Err yields StartupError state");
    assert!(submit_rename_app_state(&startup).is_none());
}

#[test]
fn submit_rename_app_state_mirrors_enter_busy_for_every_variant() {
    // Cross-check: the composer must mirror `AppState::enter_busy`
    // exactly — the entry transition is `Unlocked → UnlockedBusy`
    // for both helpers and `None` for every other source.
    // `submit_rename_app_state` is a name-the-entry-point wrapper,
    // not a re-derivation; this test pins that contract so the
    // helper can't drift away from `enter_busy` without breaking
    // here first.
    let path = vault_path();
    let sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
        AppState::UnlockedBusy { path: path.clone() },
        decide_state_from_inspect(&path, Err(invalid_header_err()))
            .expect("inspect Err yields StartupError state"),
    ];
    for source in &sources {
        let mirror = source.clone().enter_busy();
        let composed = submit_rename_app_state(source);
        match (&mirror, &composed) {
            (None, None) => {}
            (Some(a), Some(b)) => {
                assert_eq!(
                    std::mem::discriminant::<AppState>(a),
                    std::mem::discriminant::<AppState>(b),
                    "composed variant must mirror enter_busy for source={source:?}",
                );
                assert_eq!(
                    a.path().map(Path::to_path_buf),
                    b.path().map(Path::to_path_buf),
                    "composed path must mirror enter_busy for source={source:?}",
                );
            }
            other => panic!(
                "composed Some/None must mirror enter_busy for source={source:?}, \
                 got {other:?}",
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// submit_add_app_state — pre-worker `Unlocked → UnlockedBusy` composer
// ---------------------------------------------------------------------------
//
// Symmetric partner of `submit_rename_app_state` for the add path:
// where `submit_rename_app_state` covers the `Unlocked → UnlockedBusy`
// handoff for the `gio::spawn_blocking Vault::mutate_and_save(|v|
// v.rename(...))` worker, `submit_add_app_state` covers the same
// `Unlocked → UnlockedBusy` handoff for the `gio::spawn_blocking
// Vault::mutate_and_save(|v| v.add(...))` worker. Both are name-the-
// entry-point wrappers over `AppState::enter_busy()` so the call site
// in `AppModel::update` documents which typed dispatch is opening the
// busy gate. Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Vault interaction".

#[test]
fn submit_add_app_state_from_unlocked_returns_unlocked_busy_preserving_path() {
    // Happy path: `AppModel::update` receives the validated
    // `AddAccountOutput::Submit{Manual,Uri}` while the model is
    // `AppState::Unlocked(path)`. The composer must hand `AppModel`
    // the `UnlockedBusy(path)` transition that opens the busy gate
    // for the `gio::spawn_blocking Vault::mutate_and_save(|v|
    // v.add(account))` worker. The resolved path is preserved
    // verbatim so the rest of `AppModel` (account list, header bar,
    // dialog chrome) still names the same vault destination.
    let path = vault_path();
    let unlocked = AppState::Unlocked { path: path.clone() };
    let next = submit_add_app_state(&unlocked)
        .expect("Unlocked must transition to UnlockedBusy on submit");
    assert!(matches!(next, AppState::UnlockedBusy { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn submit_add_app_state_from_non_unlocked_returns_none() {
    // Defensive: a stray `AddAccountOutput::Submit{Manual,Uri}`
    // dispatch from any source state other than `Unlocked` is a no-op
    // for the state machine. `Missing` / `Locked` have no live
    // `(Vault, Store)` pair to hand off, `UnlockedBusy` already
    // serializes through one worker per §"In-flight effect ownership",
    // and `StartupError` is the non-mutating surface. Returning `None`
    // matches `AppState::enter_busy`'s own refusal contract so
    // `AppModel::update` leaves the source state in place rather than
    // installing a phantom `UnlockedBusy` that would clobber the idle
    // state.
    let path = vault_path();
    assert!(submit_add_app_state(&AppState::Missing { path: path.clone() }).is_none());
    assert!(submit_add_app_state(&AppState::Locked { path: path.clone() }).is_none());
    assert!(submit_add_app_state(&AppState::UnlockedBusy { path: path.clone() }).is_none());
    let startup = decide_state_from_inspect(&path, Err(invalid_header_err()))
        .expect("inspect Err yields StartupError state");
    assert!(submit_add_app_state(&startup).is_none());
}

#[test]
fn submit_add_app_state_mirrors_enter_busy_for_every_variant() {
    // Cross-check: the composer must mirror `AppState::enter_busy`
    // exactly — the entry transition is `Unlocked → UnlockedBusy` for
    // both helpers and `None` for every other source.
    // `submit_add_app_state` is a name-the-entry-point wrapper, not a
    // re-derivation; this test pins that contract so the helper can't
    // drift away from `enter_busy` without breaking here first.
    let path = vault_path();
    let sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
        AppState::UnlockedBusy { path: path.clone() },
        decide_state_from_inspect(&path, Err(invalid_header_err()))
            .expect("inspect Err yields StartupError state"),
    ];
    for source in &sources {
        let mirror = source.clone().enter_busy();
        let composed = submit_add_app_state(source);
        match (&mirror, &composed) {
            (None, None) => {}
            (Some(a), Some(b)) => {
                assert_eq!(
                    std::mem::discriminant::<AppState>(a),
                    std::mem::discriminant::<AppState>(b),
                    "composed variant must mirror enter_busy for source={source:?}",
                );
                assert_eq!(
                    a.path().map(Path::to_path_buf),
                    b.path().map(Path::to_path_buf),
                    "composed path must mirror enter_busy for source={source:?}",
                );
            }
            other => panic!(
                "composed Some/None must mirror enter_busy for source={source:?}, \
                 got {other:?}",
            ),
        }
    }
}

#[test]
fn submit_add_app_state_agrees_with_submit_rename_app_state() {
    // Both `submit_add_app_state` and `submit_rename_app_state` are
    // name-the-entry-point wrappers over `AppState::enter_busy` for
    // the same `Unlocked → UnlockedBusy` handoff — the rename worker
    // and the add worker both consume the already-decrypted
    // `(Vault, Store)` pair through `Vault::mutate_and_save`. Pin
    // that they agree on Some/None and produce equivalent variant /
    // path so a future refactor of either composer can't silently
    // diverge.
    let path = vault_path();
    let sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
        AppState::UnlockedBusy { path: path.clone() },
        decide_state_from_inspect(&path, Err(invalid_header_err()))
            .expect("inspect Err yields StartupError state"),
    ];
    for source in &sources {
        let add = submit_add_app_state(source);
        let rename = submit_rename_app_state(source);
        match (&add, &rename) {
            (None, None) => {}
            (Some(a), Some(r)) => {
                assert_eq!(
                    std::mem::discriminant::<AppState>(a),
                    std::mem::discriminant::<AppState>(r),
                    "add composer must produce same variant as rename composer for \
                     source={source:?}",
                );
                assert_eq!(
                    a.path().map(Path::to_path_buf),
                    r.path().map(Path::to_path_buf),
                    "add composer must produce same path as rename composer for \
                     source={source:?}",
                );
            }
            other => panic!(
                "submit_add_app_state and submit_rename_app_state must agree on Some/None for \
                 source={source:?}, got {other:?}",
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// compose_rename_worker_input — pre-worker `(Vault, Store, AccountId,
//                                            label, now)` bundler
// ---------------------------------------------------------------------------
//
// Symmetric partner of `compose_unlock_worker_input` on the rename
// path: where the unlock composer captures the resolved path plus the
// typed `VaultLock` for the `gio::spawn_blocking paladin_core::open`
// worker, the rename composer captures the live `(Vault, Store)` pair
// plus the `RenameDialogOutput::SubmitLabel` payload (account id,
// trimmed label) and the dispatch-site wall-clock for the
// `gio::spawn_blocking Vault::mutate_and_save(|v| v.rename(...))`
// worker. Both composers gate on the pre-transition source state
// (`Locked` for unlock, `Unlocked` for rename) so `AppModel::update`
// can call the composer before `submit_*_app_state` consumes the
// variant.
//
// `compose_rename_worker_input` returns `Result<RenameWorkerInput,
// (Vault, Store)>` rather than `Option` because the
// `(Vault, Store)` pair is non-`Clone` and represents live unlocked
// state — dropping it on a stray dispatch would lose the user's open
// vault. The `Err((vault, store))` branch returns the pair so the
// caller can put it back in `AppModel.vault`.

/// Build a fresh plaintext `(Vault, Store)` pair under a unique
/// tempdir for the `compose_rename_worker_input` fixtures. Returns
/// the tempdir as well so the caller keeps it alive for the duration
/// of the test — `Store::open` only needs the file to exist at the
/// time of the open call.
fn fresh_plaintext_pair() -> (tempfile::TempDir, PathBuf, Vault, Store) {
    use std::os::unix::fs::PermissionsExt;
    let tempdir = tempfile::tempdir()
        .expect("create tempdir for compose_rename_worker_input plaintext fixture");
    std::fs::set_permissions(tempdir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod tempdir to 0700 so Store::create accepts it");
    let path = tempdir.path().join("vault.bin");
    let (vault, store) = paladin_core::Store::create(&path, paladin_core::VaultInit::Plaintext)
        .expect("create plaintext vault for compose_rename_worker_input fixture");
    vault.save(&store).expect("persist plaintext vault to disk");
    let (vault, store) = paladin_core::Store::open(&path, paladin_core::VaultLock::Plaintext)
        .expect("reopen the plaintext vault for the test fixture");
    (tempdir, path, vault, store)
}

#[test]
fn compose_rename_worker_input_from_unlocked_bundles_pair_and_payload() {
    // Happy path: `AppModel::update` receives
    // `RenameDialogOutput::SubmitLabel` while the model is
    // `AppState::Unlocked(path)` with the live `(Vault, Store)` pair
    // available in the sibling `Option<(Vault, Store)>` slot. The
    // composer must move the pair plus the payload (account id,
    // trimmed label, captured `SystemTime`) into a `RenameWorkerInput`
    // so the `gio::spawn_blocking` closure can hand the bundle
    // straight to `run_rename_worker`.
    let (_tempdir, path, vault, store) = fresh_plaintext_pair();
    let unlocked = AppState::Unlocked { path: path.clone() };
    let account_id = AccountId::new();
    let label = "renamed".to_string();
    let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(12_345);

    let input: RenameWorkerInput =
        compose_rename_worker_input(&unlocked, (vault, store), account_id, label, now)
            .expect("Unlocked source must produce a RenameWorkerInput");

    assert_eq!(input.account_id, account_id);
    assert_eq!(input.label, "renamed");
    assert_eq!(input.now, now);
    // The `(Vault, Store)` pair moved into the bundle; smoke-check
    // the carried vault still names the same `Store` by exercising
    // a no-op `mutate_and_save` on a fresh, empty account list.
    assert_eq!(
        input.vault.summaries().count(),
        0,
        "fresh plaintext vault should carry zero accounts into the worker bundle",
    );
}

#[test]
fn compose_rename_worker_input_from_non_unlocked_returns_pair_back() {
    // Defensive: a stray `SubmitLabel` dispatch from any source
    // other than `Unlocked` is a no-op for the worker spawn. The
    // composer must hand the `(Vault, Store)` pair back via
    // `Err((vault, store))` so the caller can restore it into
    // `AppModel.vault` instead of leaking the live unlocked state.
    let account_id = AccountId::new();
    let label = "renamed".to_string();
    let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(12_345);
    for variant in ["missing", "locked", "unlocked_busy", "startup_error"] {
        let (_tempdir, path, vault, store) = fresh_plaintext_pair();
        let source = match variant {
            "missing" => AppState::Missing { path: path.clone() },
            "locked" => AppState::Locked { path: path.clone() },
            "unlocked_busy" => AppState::UnlockedBusy { path: path.clone() },
            "startup_error" => decide_state_from_inspect(&path, Err(invalid_header_err()))
                .expect("inspect Err yields StartupError state"),
            _ => unreachable!(),
        };
        let outcome =
            compose_rename_worker_input(&source, (vault, store), account_id, label.clone(), now);
        let Err((returned_vault, _returned_store)) = outcome else {
            panic!(
                "compose_rename_worker_input must return the pair back via Err for variant={variant}",
            );
        };
        assert_eq!(
            returned_vault.summaries().count(),
            0,
            "returned vault must still be the same live pair for variant={variant}",
        );
    }
}

#[test]
fn compose_rename_worker_input_mirrors_submit_rename_app_state_gating() {
    // Cross-check: the two entry-side rename composers — state
    // transition (`submit_rename_app_state`) and worker bundling
    // (`compose_rename_worker_input`) — must agree on the
    // `Some`/`None` (resp. `Ok`/`Err`) gating decision so
    // `AppModel::update` can call them in series without either one
    // accepting a dispatch the other refuses.
    let account_id = AccountId::new();
    let label = "renamed".to_string();
    let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(12_345);
    for variant in [
        "missing",
        "locked",
        "unlocked",
        "unlocked_busy",
        "startup_error",
    ] {
        let (_tempdir, path, vault, store) = fresh_plaintext_pair();
        let source = match variant {
            "missing" => AppState::Missing { path: path.clone() },
            "locked" => AppState::Locked { path: path.clone() },
            "unlocked" => AppState::Unlocked { path: path.clone() },
            "unlocked_busy" => AppState::UnlockedBusy { path: path.clone() },
            "startup_error" => decide_state_from_inspect(&path, Err(invalid_header_err()))
                .expect("inspect Err yields StartupError state"),
            _ => unreachable!(),
        };
        let submit_ok = submit_rename_app_state(&source).is_some();
        let worker_ok =
            compose_rename_worker_input(&source, (vault, store), account_id, label.clone(), now)
                .is_ok();
        assert_eq!(
            submit_ok, worker_ok,
            "submit_rename_app_state and compose_rename_worker_input must agree on Ok/Err \
             for variant={variant}: submit_ok={submit_ok}, worker_ok={worker_ok}",
        );
    }
}

// ---------------------------------------------------------------------------
// compose_add_worker_input — pre-worker `(Vault, Store, Account)` bundler
// ---------------------------------------------------------------------------
//
// Symmetric partner of `compose_rename_worker_input` on the add path:
// where the rename composer captures the live `(Vault, Store)` pair
// plus the `RenameDialogOutput::SubmitLabel` payload (account id,
// trimmed label, dispatch-site wall-clock) for the
// `gio::spawn_blocking Vault::mutate_and_save(|v| v.rename(...))`
// worker, the add composer captures the live `(Vault, Store)` pair
// plus the `ValidatedAccount::account` extracted from
// `classify_manual_submit` / `classify_uri_submit` for the
// `gio::spawn_blocking Vault::mutate_and_save(|v| v.add(account))`
// worker. Both composers gate on the pre-transition source state
// (`Unlocked` for both — the add and rename workers each consume the
// already-decrypted live pair) so `AppModel::update` can call the
// composer before `submit_add_app_state` consumes the variant.
//
// `compose_add_worker_input` returns `Result<AddWorkerInput,
// (Vault, Store)>` rather than `Option` because the
// `(Vault, Store)` pair is non-`Clone` and represents live unlocked
// state — dropping it on a stray dispatch would lose the user's open
// vault. The `Err((vault, store))` branch returns the pair so the
// caller can put it back in `AppModel.vault`. The `Account` payload
// itself does derive `Clone`, but the composer consumes it by value
// so the worker bundle can move into `gio::spawn_blocking` without
// borrowing from the dialog's reactive state.

/// Build a validated TOTP `Account` for the
/// `compose_add_worker_input` fixtures. Wraps the same
/// `validate_manual(AccountInput { ... })` shape the
/// `AddAccountComponent` manual sub-path drives so the test fixture
/// matches the production path without re-deriving the validation
/// pipeline.
fn fresh_add_account() -> paladin_core::Account {
    use paladin_core::{validate_manual, AccountInput, AccountKindInput, Algorithm, IconHintInput};
    use secrecy::SecretString;

    let input = AccountInput {
        label: "added-label".to_string(),
        issuer: Some("added-issuer".to_string()),
        secret: SecretString::from("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Totp,
        period_secs: None,
        counter: None,
        icon_hint: IconHintInput::Default,
    };
    validate_manual(input, SystemTime::UNIX_EPOCH)
        .expect("totp account input validates for compose_add_worker_input fixture")
        .account
}

#[test]
fn compose_add_worker_input_from_unlocked_bundles_pair_and_account() {
    // Happy path: `AppModel::update` receives an
    // `AddAccountOutput::Submit{Manual,Uri}` while the model is
    // `AppState::Unlocked(path)` with the live `(Vault, Store)` pair
    // available in the sibling `Option<(Vault, Store)>` slot. The
    // composer must move the pair plus the validated `Account` into
    // an `AddWorkerInput` so the `gio::spawn_blocking` closure can
    // hand the bundle straight to `run_add_worker`.
    let (_tempdir, path, vault, store) = fresh_plaintext_pair();
    let unlocked = AppState::Unlocked { path: path.clone() };
    let account = fresh_add_account();
    let expected_id = account.id();
    let expected_label = account.label().to_string();

    let input: AddWorkerInput = compose_add_worker_input(&unlocked, (vault, store), account)
        .expect("Unlocked source must produce an AddWorkerInput");

    assert_eq!(
        input.account.id(),
        expected_id,
        "composer must preserve the AccountId stamped at validation time",
    );
    assert_eq!(
        input.account.label(),
        expected_label,
        "composer must preserve the validated label verbatim",
    );
    // The `(Vault, Store)` pair moved into the bundle; smoke-check
    // the carried vault still names the same `Store` by exercising
    // a no-op `mutate_and_save` on a fresh, empty account list.
    assert_eq!(
        input.vault.summaries().count(),
        0,
        "fresh plaintext vault should carry zero accounts into the worker bundle",
    );
}

#[test]
fn compose_add_worker_input_from_non_unlocked_returns_pair_back() {
    // Defensive: a stray `AddAccountOutput::Submit{Manual,Uri}`
    // dispatch from any source other than `Unlocked` is a no-op for
    // the worker spawn. The composer must hand the `(Vault, Store)`
    // pair back via `Err((vault, store))` so the caller can restore
    // it into `AppModel.vault` instead of leaking the live unlocked
    // state. The `Account` payload is dropped — it carries no
    // filesystem state and the dialog still owns the reactive copy
    // for re-rendering inline if the dispatch was unexpected.
    for variant in ["missing", "locked", "unlocked_busy", "startup_error"] {
        let (_tempdir, path, vault, store) = fresh_plaintext_pair();
        let source = match variant {
            "missing" => AppState::Missing { path: path.clone() },
            "locked" => AppState::Locked { path: path.clone() },
            "unlocked_busy" => AppState::UnlockedBusy { path: path.clone() },
            "startup_error" => decide_state_from_inspect(&path, Err(invalid_header_err()))
                .expect("inspect Err yields StartupError state"),
            _ => unreachable!(),
        };
        let account = fresh_add_account();
        let outcome = compose_add_worker_input(&source, (vault, store), account);
        let Err((returned_vault, _returned_store)) = outcome else {
            panic!(
                "compose_add_worker_input must return the pair back via Err for variant={variant}",
            );
        };
        assert_eq!(
            returned_vault.summaries().count(),
            0,
            "returned vault must still be the same live pair for variant={variant}",
        );
    }
}

#[test]
fn compose_add_worker_input_mirrors_submit_add_app_state_gating() {
    // Cross-check: the two entry-side add composers — state
    // transition (`submit_add_app_state`) and worker bundling
    // (`compose_add_worker_input`) — must agree on the `Some`/`None`
    // (resp. `Ok`/`Err`) gating decision so `AppModel::update` can
    // call them in series without either one accepting a dispatch
    // the other refuses. This mirrors the equivalent cross-check
    // between `submit_rename_app_state` and
    // `compose_rename_worker_input` for the rename path.
    for variant in [
        "missing",
        "locked",
        "unlocked",
        "unlocked_busy",
        "startup_error",
    ] {
        let (_tempdir, path, vault, store) = fresh_plaintext_pair();
        let source = match variant {
            "missing" => AppState::Missing { path: path.clone() },
            "locked" => AppState::Locked { path: path.clone() },
            "unlocked" => AppState::Unlocked { path: path.clone() },
            "unlocked_busy" => AppState::UnlockedBusy { path: path.clone() },
            "startup_error" => decide_state_from_inspect(&path, Err(invalid_header_err()))
                .expect("inspect Err yields StartupError state"),
            _ => unreachable!(),
        };
        let account = fresh_add_account();
        let submit_ok = submit_add_app_state(&source).is_some();
        let worker_ok = compose_add_worker_input(&source, (vault, store), account).is_ok();
        assert_eq!(
            submit_ok, worker_ok,
            "submit_add_app_state and compose_add_worker_input must agree on Ok/Err \
             for variant={variant}: submit_ok={submit_ok}, worker_ok={worker_ok}",
        );
    }
}

#[test]
fn compose_add_worker_input_agrees_with_compose_rename_worker_input_gating() {
    // Both `compose_add_worker_input` and `compose_rename_worker_input`
    // bundle the live `(Vault, Store)` pair for a
    // `Vault::mutate_and_save` worker that needs the already-decrypted
    // pair. Pin that they agree on `Ok`/`Err` per source state so a
    // future refactor of either composer can't silently diverge on
    // the source-state contract.
    let account_id = AccountId::new();
    let label = "renamed".to_string();
    let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(12_345);
    for variant in [
        "missing",
        "locked",
        "unlocked",
        "unlocked_busy",
        "startup_error",
    ] {
        let (_tempdir, path, vault_for_add, store_for_add) = fresh_plaintext_pair();
        let (_tempdir2, _path2, vault_for_rename, store_for_rename) = fresh_plaintext_pair();
        let source = match variant {
            "missing" => AppState::Missing { path: path.clone() },
            "locked" => AppState::Locked { path: path.clone() },
            "unlocked" => AppState::Unlocked { path: path.clone() },
            "unlocked_busy" => AppState::UnlockedBusy { path: path.clone() },
            "startup_error" => decide_state_from_inspect(&path, Err(invalid_header_err()))
                .expect("inspect Err yields StartupError state"),
            _ => unreachable!(),
        };
        let account = fresh_add_account();
        let add_ok =
            compose_add_worker_input(&source, (vault_for_add, store_for_add), account).is_ok();
        let rename_ok = compose_rename_worker_input(
            &source,
            (vault_for_rename, store_for_rename),
            account_id,
            label.clone(),
            now,
        )
        .is_ok();
        assert_eq!(
            add_ok, rename_ok,
            "compose_add_worker_input and compose_rename_worker_input must agree on Ok/Err for \
             variant={variant}: add_ok={add_ok}, rename_ok={rename_ok}",
        );
    }
}

// ---------------------------------------------------------------------------
// compose_qr_worker_input — clipboard-QR add path worker bundling
// ---------------------------------------------------------------------------
//
// Symmetric partner of `compose_add_worker_input` on the QR sub-path: where
// the manual / URI add path submits a single `Account` through
// `AddWorkerInput`, the clipboard-QR sub-path submits a batch — the
// `gio::spawn_blocking Vault::mutate_and_save(|v| v.import_accounts(...))`
// worker takes the `Vec<ValidatedAccount>` produced by
// `paladin_core::import::qr_image_bytes` and merges them under
// `crate::qr_clipboard::CLIPBOARD_QR_CONFLICT_POLICY`. Both composers gate
// on the pre-transition source state (`Unlocked` only — both workers
// consume the already-decrypted live pair) so `AppModel::update` can call
// them before `submit_add_app_state` consumes the variant.
//
// `compose_qr_worker_input` returns `Result<QrWorkerInput, (Vault, Store)>`
// rather than `Option` for the same reason as `compose_add_worker_input`:
// the `(Vault, Store)` pair is non-`Clone` and represents live unlocked
// state — dropping it on a stray dispatch would lose the user's open
// vault. The `Err((vault, store))` branch returns the pair so the caller
// can put it back in `AppModel.vault`. The `Vec<ValidatedAccount>` payload
// derives no filesystem state and the secret bytes inside each `Account`
// zeroize on drop, so the refusal arm safely drops the batch.

/// Build a one-element `Vec<ValidatedAccount>` for the
/// `compose_qr_worker_input` fixtures. Wraps the same
/// `validate_manual(AccountInput { ... })` shape the
/// `paladin_core::import::qr_image_bytes` decoded-payload pipeline ends in
/// (every successfully decoded QR turns into a `ValidatedAccount`), so the
/// fixture matches the production path without re-deriving the validation
/// pipeline. Using a different label / issuer than `fresh_add_account`
/// keeps the two composer fixtures disjoint, which lets a future cross-
/// composer test distinguish them by inspection if the gating contract
/// ever changes.
fn fresh_qr_validated_accounts() -> Vec<paladin_core::ValidatedAccount> {
    use paladin_core::{validate_manual, AccountInput, AccountKindInput, Algorithm, IconHintInput};
    use secrecy::SecretString;

    let input = AccountInput {
        label: "qr-imported-label".to_string(),
        issuer: Some("qr-imported-issuer".to_string()),
        secret: SecretString::from("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Totp,
        period_secs: None,
        counter: None,
        icon_hint: IconHintInput::Default,
    };
    vec![validate_manual(input, SystemTime::UNIX_EPOCH)
        .expect("totp account input validates for compose_qr_worker_input fixture")]
}

#[test]
fn compose_qr_worker_input_from_unlocked_bundles_pair_and_accounts() {
    // Happy path: `AppModel::update` receives an
    // `AddAccountOutput::RequestScanClipboard` while the model is
    // `AppState::Unlocked(path)` with the live `(Vault, Store)` pair
    // available in the sibling `Option<(Vault, Store)>` slot. After
    // reading the clipboard texture and running
    // `crate::qr_clipboard::decode_clipboard_qr`, the composer moves
    // the pair plus the decoded `Vec<ValidatedAccount>` and the
    // dispatch-site `import_time` into a `QrWorkerInput` so the
    // `gio::spawn_blocking` closure can hand the bundle straight to
    // `run_qr_worker`.
    let (_tempdir, path, vault, store) = fresh_plaintext_pair();
    let unlocked = AppState::Unlocked { path: path.clone() };
    let accounts = fresh_qr_validated_accounts();
    let expected_label = accounts[0].account.label().to_string();
    let expected_len = accounts.len();
    let import_time = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(12_345);

    let input: QrWorkerInput =
        compose_qr_worker_input(&unlocked, (vault, store), accounts, import_time)
            .expect("Unlocked source must produce a QrWorkerInput");

    assert_eq!(
        input.accounts.len(),
        expected_len,
        "composer must preserve every decoded ValidatedAccount in the batch",
    );
    assert_eq!(
        input.accounts[0].account.label(),
        expected_label,
        "composer must preserve the validated label verbatim",
    );
    assert_eq!(
        input.import_time, import_time,
        "composer must preserve the dispatch-site import_time so a long worker queue \
         cannot stamp a stale updated_at if the merge policy ever swaps off Skip",
    );
    // The `(Vault, Store)` pair moved into the bundle; smoke-check
    // the carried vault still names the same `Store` by exercising
    // a no-op `summaries()` call on a fresh, empty account list.
    assert_eq!(
        input.vault.summaries().count(),
        0,
        "fresh plaintext vault should carry zero accounts into the worker bundle",
    );
}

#[test]
fn compose_qr_worker_input_from_non_unlocked_returns_pair_back() {
    // Defensive: a stray `AddAccountOutput::RequestScanClipboard`
    // dispatch from any source other than `Unlocked` is a no-op for
    // the worker spawn. The composer must hand the `(Vault, Store)`
    // pair back via `Err((vault, store))` so the caller can restore
    // it into `AppModel.vault` instead of leaking the live unlocked
    // state. The `Vec<ValidatedAccount>` payload is dropped — it
    // carries no filesystem state and the secret bytes inside each
    // `Account` zeroize on drop, so a refused dispatch does not leak
    // the decoded payloads.
    for variant in ["missing", "locked", "unlocked_busy", "startup_error"] {
        let (_tempdir, path, vault, store) = fresh_plaintext_pair();
        let source = match variant {
            "missing" => AppState::Missing { path: path.clone() },
            "locked" => AppState::Locked { path: path.clone() },
            "unlocked_busy" => AppState::UnlockedBusy { path: path.clone() },
            "startup_error" => decide_state_from_inspect(&path, Err(invalid_header_err()))
                .expect("inspect Err yields StartupError state"),
            _ => unreachable!(),
        };
        let accounts = fresh_qr_validated_accounts();
        let import_time = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(12_345);
        let outcome = compose_qr_worker_input(&source, (vault, store), accounts, import_time);
        let Err((returned_vault, _returned_store)) = outcome else {
            panic!(
                "compose_qr_worker_input must return the pair back via Err for variant={variant}",
            );
        };
        assert_eq!(
            returned_vault.summaries().count(),
            0,
            "returned vault must still be the same live pair for variant={variant}",
        );
    }
}

#[test]
fn compose_qr_worker_input_mirrors_submit_add_app_state_gating() {
    // Cross-check: the entry-side state transition
    // (`submit_add_app_state`, shared with the manual / URI add path
    // because the busy-gate `Unlocked → UnlockedBusy` is the same)
    // and worker bundling (`compose_qr_worker_input`) must agree on
    // the `Some`/`None` (resp. `Ok`/`Err`) gating decision so
    // `AppModel::update` can call them in series without either one
    // accepting a dispatch the other refuses. This mirrors the
    // equivalent cross-check between `submit_add_app_state` and
    // `compose_add_worker_input`.
    for variant in [
        "missing",
        "locked",
        "unlocked",
        "unlocked_busy",
        "startup_error",
    ] {
        let (_tempdir, path, vault, store) = fresh_plaintext_pair();
        let source = match variant {
            "missing" => AppState::Missing { path: path.clone() },
            "locked" => AppState::Locked { path: path.clone() },
            "unlocked" => AppState::Unlocked { path: path.clone() },
            "unlocked_busy" => AppState::UnlockedBusy { path: path.clone() },
            "startup_error" => decide_state_from_inspect(&path, Err(invalid_header_err()))
                .expect("inspect Err yields StartupError state"),
            _ => unreachable!(),
        };
        let accounts = fresh_qr_validated_accounts();
        let import_time = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(12_345);
        let submit_ok = submit_add_app_state(&source).is_some();
        let worker_ok =
            compose_qr_worker_input(&source, (vault, store), accounts, import_time).is_ok();
        assert_eq!(
            submit_ok, worker_ok,
            "submit_add_app_state and compose_qr_worker_input must agree on Ok/Err for \
             variant={variant}: submit_ok={submit_ok}, worker_ok={worker_ok}",
        );
    }
}

#[test]
fn compose_qr_worker_input_agrees_with_compose_add_worker_input_gating() {
    // Both composers bundle the live `(Vault, Store)` pair for a
    // `Vault::mutate_and_save` worker that needs the already-
    // decrypted pair. Pin that they agree on `Ok`/`Err` per source
    // state so a future refactor of either composer can't silently
    // diverge on the source-state contract — symmetric with the
    // `compose_add_worker_input_agrees_with_compose_rename_worker_input_gating`
    // cross-check on the rename path.
    let import_time = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(12_345);
    for variant in [
        "missing",
        "locked",
        "unlocked",
        "unlocked_busy",
        "startup_error",
    ] {
        let (_tempdir, path, vault_for_add, store_for_add) = fresh_plaintext_pair();
        let (_tempdir2, _path2, vault_for_qr, store_for_qr) = fresh_plaintext_pair();
        let source = match variant {
            "missing" => AppState::Missing { path: path.clone() },
            "locked" => AppState::Locked { path: path.clone() },
            "unlocked" => AppState::Unlocked { path: path.clone() },
            "unlocked_busy" => AppState::UnlockedBusy { path: path.clone() },
            "startup_error" => decide_state_from_inspect(&path, Err(invalid_header_err()))
                .expect("inspect Err yields StartupError state"),
            _ => unreachable!(),
        };
        let account = fresh_add_account();
        let accounts = fresh_qr_validated_accounts();
        let add_ok =
            compose_add_worker_input(&source, (vault_for_add, store_for_add), account).is_ok();
        let qr_ok =
            compose_qr_worker_input(&source, (vault_for_qr, store_for_qr), accounts, import_time)
                .is_ok();
        assert_eq!(
            add_ok, qr_ok,
            "compose_add_worker_input and compose_qr_worker_input must agree on Ok/Err for \
             variant={variant}: add_ok={add_ok}, qr_ok={qr_ok}",
        );
    }
}

// ---------------------------------------------------------------------------
// qr_final_app_state — unified state-transition composer (clipboard-QR add)
// ---------------------------------------------------------------------------
//
// Symmetric partner of `add_final_app_state` for the clipboard-QR sub-
// path. Both Add sub-paths share the same `Unlocked → UnlockedBusy →
// Unlocked` busy-gate lifecycle because they both consume the live
// `(Vault, Store)` pair through `Vault::mutate_and_save`. Every
// `QrWorkerEffect` variant — `Success(ImportReport)` from a successful
// `import_accounts` merge and `Failure(AddPostEffectOutcome)` for the
// `save_not_committed` / `save_durability_unconfirmed` / defensive
// `validation_error` / `invalid_state` projections — lands on the
// same `UnlockedBusy → Unlocked` rollback via `AppState::leave_busy`.
// The dialog-drop / inline-message decisions split off the effect in
// sibling composers; this composer owns only the state-machine
// roll-back.
//
// The `None` return is reserved for the defensive case where the
// completion arrives but `current` is not `UnlockedBusy` — a stray
// dispatch from an unexpected source state that should not silently
// install a phantom `Unlocked` over another idle state.

#[test]
fn qr_final_app_state_success_rolls_back_to_unlocked_preserving_path() {
    use paladin_core::ImportReport;
    use paladin_gtk::add_account::QrWorkerEffect;
    use paladin_gtk::app::state::qr_final_app_state;

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let effect = QrWorkerEffect::Success(ImportReport::default());
    let next = qr_final_app_state(&busy, &effect)
        .expect("success outcome rolls back UnlockedBusy → Unlocked");
    assert!(matches!(next, AppState::Unlocked { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn qr_final_app_state_failure_inline_rolls_back_to_unlocked_preserving_path() {
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddPostEffectOutcome, QrWorkerEffect,
    };
    use paladin_gtk::app::state::qr_final_app_state;

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let outcome = classify_add_post_effect_error(&err);
    assert!(
        matches!(outcome, AddPostEffectOutcome::Inline(_)),
        "save_not_committed routes to Inline (pinned in add_account tests)",
    );
    let effect = QrWorkerEffect::Failure(outcome);
    let next = qr_final_app_state(&busy, &effect)
        .expect("Inline failure rolls back UnlockedBusy → Unlocked (dialog stays inline)");
    assert!(matches!(next, AppState::Unlocked { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn qr_final_app_state_failure_keep_with_warning_rolls_back_to_unlocked_preserving_path() {
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddPostEffectOutcome, QrWorkerEffect,
    };
    use paladin_gtk::app::state::qr_final_app_state;

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = PaladinError::SaveDurabilityUnconfirmed;
    let outcome = classify_add_post_effect_error(&err);
    assert!(
        matches!(outcome, AddPostEffectOutcome::KeepWithWarning(_)),
        "save_durability_unconfirmed routes to KeepWithWarning",
    );
    let effect = QrWorkerEffect::Failure(outcome);
    let next = qr_final_app_state(&busy, &effect).expect(
        "KeepWithWarning failure rolls back UnlockedBusy → Unlocked (dialog keeps warning)",
    );
    assert!(matches!(next, AppState::Unlocked { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn qr_final_app_state_failure_defensive_inline_rolls_back_to_unlocked_preserving_path() {
    // Defensive: an `invalid_state` would only fire if the
    // `Vault::mutate_and_save` closure observed an unexpected
    // post-condition (e.g. the imported accounts disappeared mid-
    // flight). `classify_add_post_effect_error` routes it to `Inline`.
    // Pin the same `UnlockedBusy → Unlocked` rollback for the
    // defensive branch.
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddPostEffectOutcome, QrWorkerEffect,
    };
    use paladin_gtk::app::state::qr_final_app_state;

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = PaladinError::InvalidState {
        operation: "import",
        state: "account_not_found",
    };
    let outcome = classify_add_post_effect_error(&err);
    assert!(
        matches!(outcome, AddPostEffectOutcome::Inline(_)),
        "defensive invalid_state routes to Inline",
    );
    let effect = QrWorkerEffect::Failure(outcome);
    let next = qr_final_app_state(&busy, &effect)
        .expect("defensive Inline failure rolls back UnlockedBusy → Unlocked");
    assert!(matches!(next, AppState::Unlocked { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn qr_final_app_state_from_non_unlocked_busy_returns_none() {
    // Defensive: a stray completion arriving while `current` is not
    // `UnlockedBusy` must not silently install a phantom `Unlocked`
    // transition over another idle state. The composer mirrors the
    // `AppState::leave_busy` contract and returns `None` for every
    // non-`UnlockedBusy` source. Pinned across every typed effect so
    // the defensive arm cannot drift with the effect routing.
    use paladin_core::ImportReport;
    use paladin_gtk::add_account::{classify_add_post_effect_error, QrWorkerEffect};
    use paladin_gtk::app::state::qr_final_app_state;

    let path = vault_path();
    let effects = [
        QrWorkerEffect::Success(ImportReport::default()),
        QrWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::SaveNotCommitted {
                committed: false,
                backup_path: None,
            },
        )),
        QrWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::SaveDurabilityUnconfirmed,
        )),
        QrWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::InvalidState {
                operation: "import",
                state: "account_not_found",
            },
        )),
    ];
    let sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
        decide_state_from_inspect(&path, Err(invalid_header_err()))
            .expect("inspect Err yields StartupError state"),
    ];
    for effect in &effects {
        for source in &sources {
            assert!(
                qr_final_app_state(source, effect).is_none(),
                "qr_final_app_state must return None for non-UnlockedBusy source={source:?} effect={effect:?}",
            );
        }
    }
}

#[test]
fn qr_final_app_state_mirrors_leave_busy_for_every_variant() {
    // Cross-check: the composer is a name-the-call-site wrapper over
    // `AppState::leave_busy`, not a re-derivation. The `Some` /
    // `None` partition across source states must mirror `leave_busy`
    // byte-for-byte (and the result on `Some` must match
    // `leave_busy`'s `Unlocked { path }` projection) so the wrapper
    // can't drift away from the underlying method without breaking
    // here first. Pinned across every typed effect because the
    // composer ignores `effect` for the state decision.
    use paladin_core::ImportReport;
    use paladin_gtk::add_account::{classify_add_post_effect_error, QrWorkerEffect};
    use paladin_gtk::app::state::qr_final_app_state;

    let path = vault_path();
    let effects = [
        QrWorkerEffect::Success(ImportReport::default()),
        QrWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::SaveNotCommitted {
                committed: true,
                backup_path: None,
            },
        )),
        QrWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::SaveDurabilityUnconfirmed,
        )),
        QrWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::InvalidState {
                operation: "import",
                state: "account_not_found",
            },
        )),
    ];
    let sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
        AppState::UnlockedBusy { path: path.clone() },
        decide_state_from_inspect(&path, Err(invalid_header_err()))
            .expect("inspect Err yields StartupError state"),
    ];
    for effect in &effects {
        for source in &sources {
            let composed = qr_final_app_state(source, effect);
            let direct = source.clone().leave_busy();
            match (&composed, &direct) {
                (Some(a), Some(b)) => {
                    assert_eq!(
                        std::mem::discriminant::<AppState>(a),
                        std::mem::discriminant::<AppState>(b),
                        "wrapper variant must mirror leave_busy for source={source:?} effect={effect:?}",
                    );
                    assert_eq!(
                        a.path().map(Path::to_path_buf),
                        b.path().map(Path::to_path_buf),
                        "wrapper path must mirror leave_busy for source={source:?} effect={effect:?}",
                    );
                }
                (None, None) => {}
                _ => panic!(
                    "wrapper / leave_busy Some/None partition diverged for source={source:?} effect={effect:?}: composed={composed:?} direct={direct:?}",
                ),
            }
        }
    }
}

#[test]
fn qr_final_app_state_agrees_with_add_final_app_state_for_failure_branches() {
    // Cross-check: both the manual / URI add path and the clipboard-
    // QR sub-path consume the live `(Vault, Store)` pair through
    // `Vault::mutate_and_save`, share the same `AddPostEffectOutcome`
    // failure routing, and the busy-gate always releases on every
    // typed effect. Pin that `qr_final_app_state` agrees with
    // `add_final_app_state` for every shared failure branch so the
    // two paths cannot drift on the state-machine rollback. The
    // `Success` variants carry different payloads
    // (`AddWorkerEffect::Success { account_id }` vs.
    // `QrWorkerEffect::Success(ImportReport)`) but both share the
    // `UnlockedBusy → Unlocked` rollback because the busy gate is
    // payload-independent — pinned by the dedicated
    // `qr_final_app_state_success_rolls_back_to_unlocked_preserving_path`
    // / `add_final_app_state_success_rolls_back_to_unlocked_preserving_path`
    // siblings.
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddWorkerEffect, QrWorkerEffect,
    };
    use paladin_gtk::app::state::{add_final_app_state, qr_final_app_state};

    let path = vault_path();
    let sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
        AppState::UnlockedBusy { path: path.clone() },
        decide_state_from_inspect(&path, Err(invalid_header_err()))
            .expect("inspect Err yields StartupError state"),
    ];
    let errs = [
        PaladinError::SaveNotCommitted {
            committed: false,
            backup_path: None,
        },
        PaladinError::SaveDurabilityUnconfirmed,
        PaladinError::InvalidState {
            operation: "import",
            state: "account_not_found",
        },
    ];
    for source in &sources {
        for err in &errs {
            let outcome = classify_add_post_effect_error(err);
            let add_effect = AddWorkerEffect::Failure(outcome.clone());
            let qr_effect = QrWorkerEffect::Failure(outcome);
            let add_next = add_final_app_state(source, &add_effect);
            let qr_next = qr_final_app_state(source, &qr_effect);
            match (&add_next, &qr_next) {
                (Some(a), Some(b)) => {
                    assert_eq!(
                        std::mem::discriminant::<AppState>(a),
                        std::mem::discriminant::<AppState>(b),
                        "add/qr final state must agree on variant for source={source:?} err={err:?}",
                    );
                    assert_eq!(
                        a.path().map(Path::to_path_buf),
                        b.path().map(Path::to_path_buf),
                        "add/qr final state must agree on path for source={source:?} err={err:?}",
                    );
                }
                (None, None) => {}
                _ => panic!(
                    "add/qr final state Some/None partition diverged for source={source:?} err={err:?}: add={add_next:?} qr={qr_next:?}",
                ),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// should_drop_add_dialog_after_qr — clipboard-QR dialog-drop projection
// ---------------------------------------------------------------------------
//
// Symmetric partner of `should_drop_add_dialog_after` for the
// clipboard-QR sub-path. Diverges from the manual / URI add path on
// `Success`: where the manual / URI flow drops the dialog after a
// successful add (the new row appears in the visible list and there
// is nothing more to show), the QR sub-path keeps the dialog
// mounted so the counts panel can render the `imported / skipped /
// warning` numbers parked by `QrImportSummary::from_report`. The
// failure projections (`AddPostEffectOutcome::Inline` for
// `save_not_committed` / `io_error` / defensive `validation_error`
// / `invalid_state` and `KeepWithWarning` for
// `save_durability_unconfirmed`) also keep the dialog mounted so
// the inline error / durability warning is visible and the user
// can retry or acknowledge — same contract as the manual / URI
// failure branches.
//
// The projection therefore returns `false` for every typed
// `QrWorkerEffect` variant, matching the post-commit "the dialog
// stays open" semantics for the QR sub-path.

#[test]
fn should_drop_add_dialog_after_qr_returns_false_on_success() {
    use paladin_core::ImportReport;
    use paladin_gtk::add_account::QrWorkerEffect;
    use paladin_gtk::app::state::should_drop_add_dialog_after_qr;

    let effect = QrWorkerEffect::Success(ImportReport::default());
    assert!(
        !should_drop_add_dialog_after_qr(&effect),
        "QR Success keeps the Add dialog mounted so the counts panel can render",
    );
}

#[test]
fn should_drop_add_dialog_after_qr_returns_false_on_failure_inline() {
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddPostEffectOutcome, QrWorkerEffect,
    };
    use paladin_gtk::app::state::should_drop_add_dialog_after_qr;

    let outcome = classify_add_post_effect_error(&PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    });
    assert!(
        matches!(outcome, AddPostEffectOutcome::Inline(_)),
        "save_not_committed routes to Inline",
    );
    let effect = QrWorkerEffect::Failure(outcome);
    assert!(
        !should_drop_add_dialog_after_qr(&effect),
        "Inline failure keeps the Add dialog mounted so the inline error renders",
    );
}

#[test]
fn should_drop_add_dialog_after_qr_returns_false_on_failure_keep_with_warning() {
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddPostEffectOutcome, QrWorkerEffect,
    };
    use paladin_gtk::app::state::should_drop_add_dialog_after_qr;

    let outcome = classify_add_post_effect_error(&PaladinError::SaveDurabilityUnconfirmed);
    assert!(
        matches!(outcome, AddPostEffectOutcome::KeepWithWarning(_)),
        "save_durability_unconfirmed routes to KeepWithWarning",
    );
    let effect = QrWorkerEffect::Failure(outcome);
    assert!(
        !should_drop_add_dialog_after_qr(&effect),
        "KeepWithWarning failure keeps the Add dialog mounted so the warning renders",
    );
}

#[test]
fn should_drop_add_dialog_after_qr_returns_false_for_defensive_inline() {
    // Defensive: an `invalid_state` would only fire if
    // `Vault::mutate_and_save`'s closure observed an unexpected
    // post-condition. `classify_add_post_effect_error` routes it to
    // `Inline`. Same "stay mounted" rule applies so the typed
    // error renders.
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddPostEffectOutcome, QrWorkerEffect,
    };
    use paladin_gtk::app::state::should_drop_add_dialog_after_qr;

    let outcome = classify_add_post_effect_error(&PaladinError::InvalidState {
        operation: "import",
        state: "account_not_found",
    });
    assert!(
        matches!(outcome, AddPostEffectOutcome::Inline(_)),
        "defensive invalid_state routes to Inline",
    );
    let effect = QrWorkerEffect::Failure(outcome);
    assert!(
        !should_drop_add_dialog_after_qr(&effect),
        "defensive Inline failure keeps the Add dialog mounted",
    );
}

#[test]
fn should_drop_add_dialog_after_qr_diverges_from_add_on_success() {
    // Cross-check: the QR sub-path's `Success` projection must NOT
    // mirror the manual / URI add path — the QR sub-path keeps the
    // dialog mounted on success so the counts panel can render the
    // post-merge counts, while the manual / URI add path drops the
    // dialog because the new row's only surface is the visible
    // account list. Pin the divergence so a future refactor of either
    // projection can't silently align them and erase the counts
    // panel.
    use paladin_core::{AccountId, ImportReport};
    use paladin_gtk::add_account::{AddWorkerEffect, QrWorkerEffect};
    use paladin_gtk::app::state::{should_drop_add_dialog_after, should_drop_add_dialog_after_qr};

    let add_effect = AddWorkerEffect::Success {
        account_id: AccountId::new(),
    };
    let qr_effect = QrWorkerEffect::Success(ImportReport::default());
    assert!(
        should_drop_add_dialog_after(&add_effect),
        "manual / URI add path drops the Add dialog on Success",
    );
    assert!(
        !should_drop_add_dialog_after_qr(&qr_effect),
        "QR sub-path keeps the Add dialog mounted on Success (counts panel)",
    );
}

#[test]
fn should_drop_add_dialog_after_qr_mirrors_add_on_failure() {
    // Cross-check: the failure projections (`Inline` and
    // `KeepWithWarning`) share the "stay mounted" rule between the
    // manual / URI add path and the QR sub-path because both keep
    // the dialog open so the inline error / durability warning is
    // visible. Pin the agreement so a future refactor of either
    // projection cannot silently diverge on the failure branches.
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddWorkerEffect, QrWorkerEffect,
    };
    use paladin_gtk::app::state::{should_drop_add_dialog_after, should_drop_add_dialog_after_qr};

    let errs = [
        PaladinError::SaveNotCommitted {
            committed: false,
            backup_path: None,
        },
        PaladinError::SaveDurabilityUnconfirmed,
        PaladinError::InvalidState {
            operation: "import",
            state: "account_not_found",
        },
    ];
    for err in &errs {
        let outcome = classify_add_post_effect_error(err);
        let add_effect = AddWorkerEffect::Failure(outcome.clone());
        let qr_effect = QrWorkerEffect::Failure(outcome);
        assert_eq!(
            should_drop_add_dialog_after(&add_effect),
            should_drop_add_dialog_after_qr(&qr_effect),
            "add/qr Failure drop decisions must agree for err={err:?}",
        );
    }
}

// ---------------------------------------------------------------------------
// should_refresh_list_after_qr — clipboard-QR list-refresh projection
// ---------------------------------------------------------------------------
//
// Symmetric partner of `should_refresh_list_after_add` for the
// clipboard-QR sub-path. Both pivot on whether the vault is
// committed-or-uncertain (refresh) versus rolled-back (no refresh).
// Success and `KeepWithWarning` mean the import landed durably (or
// at least at the bincode-payload level), so the visible row set
// must surface the newly merged accounts; `Inline` (every
// `save_not_committed` / `io_error` / defensive `validation_error`
// / `invalid_state` projection) means `Vault::mutate_and_save`
// restored its pre-attempt snapshot, so the visible rows already
// match disk and no refresh is needed.

#[test]
fn should_refresh_list_after_qr_returns_true_on_success() {
    use paladin_core::ImportReport;
    use paladin_gtk::add_account::QrWorkerEffect;
    use paladin_gtk::app::state::should_refresh_list_after_qr;

    let effect = QrWorkerEffect::Success(ImportReport::default());
    assert!(
        should_refresh_list_after_qr(&effect),
        "QR Success refreshes the visible list so newly imported accounts surface",
    );
}

#[test]
fn should_refresh_list_after_qr_returns_false_on_failure_inline() {
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddPostEffectOutcome, QrWorkerEffect,
    };
    use paladin_gtk::app::state::should_refresh_list_after_qr;

    let outcome = classify_add_post_effect_error(&PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    });
    assert!(matches!(outcome, AddPostEffectOutcome::Inline(_)));
    let effect = QrWorkerEffect::Failure(outcome);
    assert!(
        !should_refresh_list_after_qr(&effect),
        "Inline failure rolls back the import; visible rows already match disk",
    );
}

#[test]
fn should_refresh_list_after_qr_returns_true_on_failure_keep_with_warning() {
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddPostEffectOutcome, QrWorkerEffect,
    };
    use paladin_gtk::app::state::should_refresh_list_after_qr;

    let outcome = classify_add_post_effect_error(&PaladinError::SaveDurabilityUnconfirmed);
    assert!(matches!(outcome, AddPostEffectOutcome::KeepWithWarning(_)));
    let effect = QrWorkerEffect::Failure(outcome);
    assert!(
        should_refresh_list_after_qr(&effect),
        "KeepWithWarning leaves the merged accounts in memory; list must surface them",
    );
}

#[test]
fn should_refresh_list_after_qr_returns_false_for_defensive_inline() {
    // Defensive: `invalid_state` would only fire if
    // `Vault::mutate_and_save`'s closure observed an unexpected
    // post-condition; the vault was not mutated, so no refresh.
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddPostEffectOutcome, QrWorkerEffect,
    };
    use paladin_gtk::app::state::should_refresh_list_after_qr;

    let outcome = classify_add_post_effect_error(&PaladinError::InvalidState {
        operation: "import",
        state: "account_not_found",
    });
    assert!(matches!(outcome, AddPostEffectOutcome::Inline(_)));
    let effect = QrWorkerEffect::Failure(outcome);
    assert!(
        !should_refresh_list_after_qr(&effect),
        "defensive Inline does not mutate the vault; visible rows unchanged",
    );
}

#[test]
fn should_refresh_list_after_qr_mirrors_add_for_every_shared_branch() {
    // Cross-check: the failure projections share the same outcome
    // type (`AddPostEffectOutcome`) and the same in-memory rollback
    // semantics between the manual / URI add path and the QR sub-
    // path. The `Success` branches both refresh because the
    // committed-or-uncertain mutations leave the vault dirty.
    // Pin agreement across every typed branch so a future refactor
    // cannot silently diverge the two paths.
    use paladin_core::{AccountId, ImportReport};
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddWorkerEffect, QrWorkerEffect,
    };
    use paladin_gtk::app::state::{should_refresh_list_after_add, should_refresh_list_after_qr};

    let add_success = AddWorkerEffect::Success {
        account_id: AccountId::new(),
    };
    let qr_success = QrWorkerEffect::Success(ImportReport::default());
    assert_eq!(
        should_refresh_list_after_add(&add_success),
        should_refresh_list_after_qr(&qr_success),
        "add/qr Success branches must agree on refresh decision",
    );
    let errs = [
        PaladinError::SaveNotCommitted {
            committed: false,
            backup_path: None,
        },
        PaladinError::SaveDurabilityUnconfirmed,
        PaladinError::InvalidState {
            operation: "import",
            state: "account_not_found",
        },
    ];
    for err in &errs {
        let outcome = classify_add_post_effect_error(err);
        let add_effect = AddWorkerEffect::Failure(outcome.clone());
        let qr_effect = QrWorkerEffect::Failure(outcome);
        assert_eq!(
            should_refresh_list_after_add(&add_effect),
            should_refresh_list_after_qr(&qr_effect),
            "add/qr Failure refresh decisions must agree for err={err:?}",
        );
    }
}

// ---------------------------------------------------------------------------
// qr_dialog_msg_after — clipboard-QR inline-message projection
// ---------------------------------------------------------------------------
//
// Symmetric partner of `add_dialog_msg_after` for the clipboard-QR
// sub-path. Both project the worker's typed outcome into the
// downstream `AddAccountMsg` that `AppModel::update` forwards into
// the live `AddAccountComponent` controller. Diverges from the
// manual / URI add path on `Success`: where the manual / URI flow
// returns `None` (the dialog is being dropped, so there is no
// controller to forward to), the QR sub-path returns
// `Some(AddAccountMsg::QrSuccess(summary))` so the counts panel can
// render the post-merge counts inside the still-mounted dialog. On
// every Failure branch the projection returns
// `Some(AddAccountMsg::WorkerFailed(outcome.clone()))` so the
// dialog can re-render the inline error / durability warning —
// same contract as the manual / URI failure branches.

#[test]
fn qr_dialog_msg_after_success_returns_qr_success_with_summary_from_report() {
    use paladin_core::{AccountId, ImportReport};
    use paladin_gtk::add_account::{AddAccountMsg, QrWorkerEffect};
    use paladin_gtk::app::state::qr_dialog_msg_after;
    use paladin_gtk::qr_clipboard::QrImportSummary;

    let report = ImportReport {
        imported: 3,
        skipped: 1,
        replaced: 0,
        appended: 0,
        accounts: vec![AccountId::new(), AccountId::new(), AccountId::new()],
        warnings: Vec::new(),
    };
    let expected = QrImportSummary::from_report(&report);
    let effect = QrWorkerEffect::Success(report);
    match qr_dialog_msg_after(&effect) {
        Some(AddAccountMsg::QrSuccess(summary)) => {
            assert_eq!(
                summary, expected,
                "QrSuccess must carry the QrImportSummary::from_report projection",
            );
        }
        other => panic!(
            "QrWorkerEffect::Success must project to Some(AddAccountMsg::QrSuccess(_)), got {other:?}",
        ),
    }
}

#[test]
fn qr_dialog_msg_after_failure_inline_returns_worker_failed_inline() {
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddAccountMsg, AddPostEffectOutcome, QrWorkerEffect,
    };
    use paladin_gtk::app::state::qr_dialog_msg_after;

    let outcome = classify_add_post_effect_error(&PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    });
    assert!(matches!(outcome, AddPostEffectOutcome::Inline(_)));
    let effect = QrWorkerEffect::Failure(outcome);
    match qr_dialog_msg_after(&effect) {
        Some(AddAccountMsg::WorkerFailed(AddPostEffectOutcome::Inline(_))) => {}
        other => panic!(
            "Inline failure must project to Some(AddAccountMsg::WorkerFailed(Inline)), got {other:?}",
        ),
    }
}

#[test]
fn qr_dialog_msg_after_failure_keep_with_warning_returns_worker_failed_keep_with_warning() {
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddAccountMsg, AddPostEffectOutcome, QrWorkerEffect,
    };
    use paladin_gtk::app::state::qr_dialog_msg_after;

    let outcome = classify_add_post_effect_error(&PaladinError::SaveDurabilityUnconfirmed);
    assert!(matches!(outcome, AddPostEffectOutcome::KeepWithWarning(_)));
    let effect = QrWorkerEffect::Failure(outcome);
    match qr_dialog_msg_after(&effect) {
        Some(AddAccountMsg::WorkerFailed(AddPostEffectOutcome::KeepWithWarning(_))) => {}
        other => panic!(
            "KeepWithWarning failure must project to Some(AddAccountMsg::WorkerFailed(KeepWithWarning)), got {other:?}",
        ),
    }
}

#[test]
fn qr_dialog_msg_after_diverges_from_add_on_success() {
    // Cross-check: the manual / URI add path's `Success` returns
    // `None` because the dialog is being dropped. The QR sub-path's
    // `Success` must return `Some(QrSuccess(summary))` because the
    // dialog stays mounted to show the counts panel. Pin the
    // divergence so a future refactor cannot silently align them
    // and erase the counts panel surface.
    use paladin_core::{AccountId, ImportReport};
    use paladin_gtk::add_account::{AddAccountMsg, AddWorkerEffect, QrWorkerEffect};
    use paladin_gtk::app::state::{add_dialog_msg_after, qr_dialog_msg_after};

    let add_effect = AddWorkerEffect::Success {
        account_id: AccountId::new(),
    };
    let qr_effect = QrWorkerEffect::Success(ImportReport::default());
    assert!(
        add_dialog_msg_after(&add_effect).is_none(),
        "manual / URI add path Success returns None (dialog drops)",
    );
    assert!(
        matches!(
            qr_dialog_msg_after(&qr_effect),
            Some(AddAccountMsg::QrSuccess(_))
        ),
        "QR sub-path Success returns Some(QrSuccess(summary)) (counts panel)",
    );
}

#[test]
fn qr_dialog_msg_after_failure_branches_mirror_add_failure_routing() {
    // Cross-check: both paths share the same outcome type
    // (`AddPostEffectOutcome`) on failure and route them identically
    // through `AddAccountMsg::WorkerFailed`. Pin parity on every
    // shared failure branch so the dialog stays the only surface
    // for inline errors / durability warnings on both sub-paths.
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddAccountMsg, AddWorkerEffect, QrWorkerEffect,
    };
    use paladin_gtk::app::state::{add_dialog_msg_after, qr_dialog_msg_after};

    let errs = [
        PaladinError::SaveNotCommitted {
            committed: false,
            backup_path: None,
        },
        PaladinError::SaveDurabilityUnconfirmed,
        PaladinError::InvalidState {
            operation: "import",
            state: "account_not_found",
        },
    ];
    for err in &errs {
        let outcome = classify_add_post_effect_error(err);
        let add_effect = AddWorkerEffect::Failure(outcome.clone());
        let qr_effect = QrWorkerEffect::Failure(outcome);
        let add_msg = add_dialog_msg_after(&add_effect);
        let qr_msg = qr_dialog_msg_after(&qr_effect);
        match (&add_msg, &qr_msg) {
            (
                Some(AddAccountMsg::WorkerFailed(ref a)),
                Some(AddAccountMsg::WorkerFailed(ref b)),
            ) => {
                assert_eq!(
                    std::mem::discriminant(a),
                    std::mem::discriminant(b),
                    "WorkerFailed outcome discriminants must agree for err={err:?}",
                );
            }
            other => panic!("add/qr failure routing diverged for err={err:?}: {other:?}",),
        }
    }
}

#[test]
fn qr_dialog_msg_after_drop_dialog_partition_inverts_add_on_success() {
    // Cross-check pin: `dialog_msg.is_some() == !drop_dialog` is the
    // contract on the manual / URI add path (a dropped dialog gets
    // no message; a mounted dialog gets a `WorkerFailed`). The QR
    // sub-path inverts this on `Success`: the dialog is NOT dropped,
    // so `dialog_msg` is `Some(QrSuccess(_))`. Pin both sides of
    // the partition so the dispatch composer below cannot drift
    // (e.g. forward a `QrSuccess` while still dropping the dialog).
    use paladin_core::ImportReport;
    use paladin_gtk::add_account::QrWorkerEffect;
    use paladin_gtk::app::state::{qr_dialog_msg_after, should_drop_add_dialog_after_qr};

    let effect = QrWorkerEffect::Success(ImportReport::default());
    assert!(
        !should_drop_add_dialog_after_qr(&effect),
        "QR Success keeps the dialog mounted",
    );
    assert!(
        qr_dialog_msg_after(&effect).is_some(),
        "QR Success forwards QrSuccess(summary) to the still-mounted dialog",
    );
}

// ---------------------------------------------------------------------------
// compose_qr_dispatch — bundle QR-worker dispatch decisions
// ---------------------------------------------------------------------------
//
// Symmetric partner of `compose_add_dispatch` for the clipboard-QR
// sub-path. `AppMsg::QrWorkerCompleted` (wired in a follow-up commit)
// consults this composer to apply the worker outcome in a single
// shot without re-routing the `QrWorkerEffect`:
//
// * `app_state` mirrors `qr_final_app_state`.
// * `dialog_msg` mirrors `qr_dialog_msg_after`.
// * `drop_dialog` mirrors `should_drop_add_dialog_after_qr` (always
//   `false` — the dialog stays mounted on every effect so the
//   counts panel / inline error / durability warning surfaces).
// * `refresh_list` mirrors `should_refresh_list_after_qr`.
//
// `success_toast` is intentionally omitted from `QrDispatch`: the
// counts panel parked by `QrSuccess(summary)` is the surface for
// the post-merge counts, so a separate `AdwToast` would be
// redundant. The plan's "Surface post-merge counts inline" rule
// for the QR sub-path is satisfied entirely by the still-mounted
// dialog.

#[test]
fn compose_qr_dispatch_success_carries_qr_success_keep_mounted_and_refresh() {
    use paladin_core::ImportReport;
    use paladin_gtk::add_account::{AddAccountMsg, QrWorkerEffect};
    use paladin_gtk::app::state::compose_qr_dispatch;
    use paladin_gtk::qr_clipboard::QrImportSummary;

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let report = ImportReport {
        imported: 2,
        skipped: 1,
        replaced: 0,
        appended: 0,
        accounts: vec![
            paladin_core::AccountId::new(),
            paladin_core::AccountId::new(),
        ],
        warnings: Vec::new(),
    };
    let expected_summary = QrImportSummary::from_report(&report);
    let effect = QrWorkerEffect::Success(report);
    let dispatch = compose_qr_dispatch(&busy, &effect);

    let new_state = dispatch
        .app_state
        .as_ref()
        .expect("Success rolls back UnlockedBusy → Unlocked");
    assert!(matches!(new_state, AppState::Unlocked { .. }));
    assert_path_eq(new_state, &path);

    match dispatch.dialog_msg.as_ref() {
        Some(AddAccountMsg::QrSuccess(summary)) => {
            assert_eq!(
                *summary, expected_summary,
                "Success forwards QrSuccess with the from_report summary",
            );
        }
        other => panic!(
            "Success must forward Some(AddAccountMsg::QrSuccess(_)) into the dialog, got {other:?}",
        ),
    }

    assert!(
        !dispatch.drop_dialog,
        "QR Success keeps the Add dialog mounted so the counts panel renders",
    );
    assert!(
        dispatch.refresh_list,
        "QR Success refreshes the list so newly merged accounts surface",
    );
}

#[test]
fn compose_qr_dispatch_failure_inline_keeps_dialog_mounted_no_refresh() {
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddAccountMsg, AddPostEffectOutcome, QrWorkerEffect,
    };
    use paladin_gtk::app::state::compose_qr_dispatch;

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let outcome = classify_add_post_effect_error(&PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    });
    assert!(matches!(outcome, AddPostEffectOutcome::Inline(_)));
    let effect = QrWorkerEffect::Failure(outcome);
    let dispatch = compose_qr_dispatch(&busy, &effect);

    let new_state = dispatch
        .app_state
        .as_ref()
        .expect("Inline failure still rolls back UnlockedBusy → Unlocked");
    assert!(matches!(new_state, AppState::Unlocked { .. }));
    assert_path_eq(new_state, &path);

    match dispatch.dialog_msg.as_ref() {
        Some(AddAccountMsg::WorkerFailed(AddPostEffectOutcome::Inline(_))) => {}
        other => panic!(
            "Inline failure must forward WorkerFailed(Inline) into the dialog, got {other:?}",
        ),
    }

    assert!(
        !dispatch.drop_dialog,
        "Inline failure keeps the dialog mounted so the inline error renders",
    );
    assert!(
        !dispatch.refresh_list,
        "Inline failure rolls back; visible rows already match disk",
    );
}

#[test]
fn compose_qr_dispatch_failure_keep_with_warning_refreshes_and_keeps_mounted() {
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddAccountMsg, AddPostEffectOutcome, QrWorkerEffect,
    };
    use paladin_gtk::app::state::compose_qr_dispatch;

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let outcome = classify_add_post_effect_error(&PaladinError::SaveDurabilityUnconfirmed);
    assert!(matches!(outcome, AddPostEffectOutcome::KeepWithWarning(_)));
    let effect = QrWorkerEffect::Failure(outcome);
    let dispatch = compose_qr_dispatch(&busy, &effect);

    let new_state = dispatch
        .app_state
        .as_ref()
        .expect("KeepWithWarning rolls back UnlockedBusy → Unlocked");
    assert!(matches!(new_state, AppState::Unlocked { .. }));
    assert_path_eq(new_state, &path);

    match dispatch.dialog_msg.as_ref() {
        Some(AddAccountMsg::WorkerFailed(AddPostEffectOutcome::KeepWithWarning(_))) => {}
        other => {
            panic!("KeepWithWarning must forward WorkerFailed(KeepWithWarning), got {other:?}",)
        }
    }

    assert!(
        !dispatch.drop_dialog,
        "KeepWithWarning keeps the dialog mounted so the warning renders",
    );
    assert!(
        dispatch.refresh_list,
        "KeepWithWarning leaves the merged accounts durable; list must surface them",
    );
}

#[test]
fn compose_qr_dispatch_from_non_unlocked_busy_carries_none_app_state() {
    // Defensive: a stray worker completion arriving while `current`
    // is not `UnlockedBusy` must not install a phantom `Unlocked`
    // rollback. The dispatch composer still projects `dialog_msg` /
    // `drop_dialog` / `refresh_list` consistently — these are
    // payload-only and the dialog routing remains valid — but
    // `app_state` carries `None` so `AppModel::update` leaves the
    // cached state untouched.
    use paladin_core::ImportReport;
    use paladin_gtk::add_account::{AddAccountMsg, QrWorkerEffect};
    use paladin_gtk::app::state::compose_qr_dispatch;

    let path = vault_path();
    let sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
        decide_state_from_inspect(&path, Err(invalid_header_err()))
            .expect("inspect Err yields StartupError state"),
    ];
    let effect = QrWorkerEffect::Success(ImportReport::default());
    for source in &sources {
        let dispatch = compose_qr_dispatch(source, &effect);
        assert!(
            dispatch.app_state.is_none(),
            "compose_qr_dispatch must carry None app_state for stray dispatch from source={source:?}",
        );
        assert!(
            matches!(
                dispatch.dialog_msg.as_ref(),
                Some(AddAccountMsg::QrSuccess(_))
            ),
            "dialog_msg still mirrors qr_dialog_msg_after for source={source:?}",
        );
        assert!(
            !dispatch.drop_dialog,
            "drop_dialog still mirrors should_drop_add_dialog_after_qr",
        );
        assert!(
            dispatch.refresh_list,
            "refresh_list still mirrors should_refresh_list_after_qr",
        );
    }
}

#[test]
fn compose_qr_dispatch_mirrors_trio_projections() {
    // Aggregator invariant: each field of `QrDispatch` must equal
    // the corresponding sibling projection across every typed
    // effect and every source state. Pinning this prevents the
    // composer from drifting from its constituent projections
    // (e.g. forwarding a `QrSuccess` while quietly dropping the
    // dialog).
    use paladin_core::ImportReport;
    use paladin_gtk::add_account::{classify_add_post_effect_error, QrWorkerEffect};
    use paladin_gtk::app::state::{
        compose_qr_dispatch, qr_dialog_msg_after, qr_final_app_state,
        should_drop_add_dialog_after_qr, should_refresh_list_after_qr,
    };

    let path = vault_path();
    let effects = [
        QrWorkerEffect::Success(ImportReport::default()),
        QrWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::SaveNotCommitted {
                committed: false,
                backup_path: None,
            },
        )),
        QrWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::SaveDurabilityUnconfirmed,
        )),
        QrWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::InvalidState {
                operation: "import",
                state: "account_not_found",
            },
        )),
    ];
    let sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
        AppState::UnlockedBusy { path: path.clone() },
        decide_state_from_inspect(&path, Err(invalid_header_err()))
            .expect("inspect Err yields StartupError state"),
    ];
    for effect in &effects {
        for source in &sources {
            let dispatch = compose_qr_dispatch(source, effect);
            let direct_state = qr_final_app_state(source, effect);
            match (&dispatch.app_state, &direct_state) {
                (Some(a), Some(b)) => {
                    assert_eq!(
                        std::mem::discriminant::<AppState>(a),
                        std::mem::discriminant::<AppState>(b),
                        "QrDispatch.app_state variant must mirror qr_final_app_state for source={source:?} effect={effect:?}",
                    );
                    assert_eq!(
                        a.path().map(Path::to_path_buf),
                        b.path().map(Path::to_path_buf),
                        "QrDispatch.app_state path must mirror qr_final_app_state for source={source:?} effect={effect:?}",
                    );
                }
                (None, None) => {}
                _ => panic!(
                    "QrDispatch.app_state Some/None partition must mirror qr_final_app_state for source={source:?} effect={effect:?}: dispatch={dispatch:?} direct={direct_state:?}",
                ),
            }
            assert_eq!(
                dispatch.drop_dialog,
                should_drop_add_dialog_after_qr(effect),
                "QrDispatch.drop_dialog must mirror should_drop_add_dialog_after_qr for source={source:?} effect={effect:?}",
            );
            assert_eq!(
                dispatch.refresh_list,
                should_refresh_list_after_qr(effect),
                "QrDispatch.refresh_list must mirror should_refresh_list_after_qr for source={source:?} effect={effect:?}",
            );
            // Presence-only check on dialog_msg: the projection
            // builds `Some(...)` for every typed effect (the dialog
            // stays mounted on Success and Failure alike), so the
            // aggregator must also carry `Some(_)` — pinned here so
            // the field cannot quietly fall to `None`.
            assert_eq!(
                dispatch.dialog_msg.is_some(),
                qr_dialog_msg_after(effect).is_some(),
                "QrDispatch.dialog_msg presence must mirror qr_dialog_msg_after for source={source:?} effect={effect:?}",
            );
        }
    }
}

// ---------------------------------------------------------------------------
// apply_submit_unlock_inplace — `AppModel::update` mut-state wrapper
// ---------------------------------------------------------------------------
//
// `submit_unlock_app_state(&AppState) -> Option<AppState>` carries the
// composer's typed refusal contract for the entry transition. The wrapper
// here lets `AppModel::update`'s `UnlockDialogOutput::SubmitLock` handler
// mutate the cached `AppState` in place without managing the take-and-
// restore dance itself — it keeps the side-effect decision unit-testable
// in `tests/app_state_logic.rs` without spinning up GTK / libadwaita.

#[test]
fn apply_submit_unlock_inplace_from_locked_mutates_to_unlocked_busy_and_returns_true() {
    // Happy path: `AppModel::update` mutates `self.state` in place via
    // the helper when `UnlockDialogOutput::SubmitLock` arrives. The
    // resolved path is preserved verbatim so the live
    // `UnlockDialogComponent` (still mounted until the worker returns)
    // names the same destination. The `true` return signals that the
    // state actually transitioned so the caller can spawn the
    // `gio::spawn_blocking paladin_core::open` worker — the `false`
    // arm of the API is the defensive no-op for stray dispatches.
    let path = vault_path();
    let mut state = AppState::Locked { path: path.clone() };
    let transitioned = apply_submit_unlock_inplace(&mut state);
    assert!(
        transitioned,
        "apply_submit_unlock_inplace must return true on the Locked → UnlockedBusy transition",
    );
    assert!(matches!(state, AppState::UnlockedBusy { .. }));
    assert_path_eq(&state, &path);
}

#[test]
fn apply_submit_unlock_inplace_from_non_locked_leaves_state_unchanged_and_returns_false() {
    // Defensive: a stray `SubmitLock` dispatch from any non-`Locked`
    // source is a no-op. The wrapped state must survive the call
    // byte-for-byte so `AppModel::update` cannot accidentally clobber
    // an idle state (`Missing` / `Unlocked` / `UnlockedBusy` /
    // `StartupError`) with a phantom `UnlockedBusy`. The `false`
    // return tells the caller not to spawn the open worker.
    let path = vault_path();
    let sources = [
        AppState::Missing { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
        AppState::UnlockedBusy { path: path.clone() },
        decide_state_from_inspect(&path, Err(invalid_header_err()))
            .expect("inspect Err yields StartupError state"),
    ];
    for source in sources {
        let original_discriminant = std::mem::discriminant::<AppState>(&source);
        let original_path = source.path().map(Path::to_path_buf);
        let mut state = source.clone();
        let transitioned = apply_submit_unlock_inplace(&mut state);
        assert!(
            !transitioned,
            "apply_submit_unlock_inplace must return false for non-Locked source={source:?}",
        );
        assert_eq!(
            std::mem::discriminant::<AppState>(&state),
            original_discriminant,
            "apply_submit_unlock_inplace must leave variant unchanged for source={source:?}",
        );
        assert_eq!(
            state.path().map(Path::to_path_buf),
            original_path,
            "apply_submit_unlock_inplace must leave path unchanged for source={source:?}",
        );
    }
}

#[test]
fn apply_submit_unlock_inplace_mirrors_submit_unlock_app_state_for_every_variant() {
    // Cross-check: the wrapper must mirror `submit_unlock_app_state`
    // exactly. It is a name-the-call-site wrapper, not a re-derivation
    // — the `true` / `false` partition matches the `Some` / `None`
    // partition of the composer, and the resulting state on `true`
    // matches the `Some(_)` variant + path the composer reports. This
    // test pins that contract so the wrapper can't drift away from
    // `submit_unlock_app_state` without breaking here first.
    let path = vault_path();
    let sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
        AppState::UnlockedBusy { path: path.clone() },
        decide_state_from_inspect(&path, Err(invalid_header_err()))
            .expect("inspect Err yields StartupError state"),
    ];
    for source in &sources {
        let composed = submit_unlock_app_state(source);
        let mut state = source.clone();
        let transitioned = apply_submit_unlock_inplace(&mut state);
        if let Some(expected) = composed {
            assert!(
                transitioned,
                "wrapper must return true when composer returns Some for source={source:?}",
            );
            assert_eq!(
                std::mem::discriminant::<AppState>(&state),
                std::mem::discriminant::<AppState>(&expected),
                "wrapper variant must mirror composer for source={source:?}",
            );
            assert_eq!(
                state.path().map(Path::to_path_buf),
                expected.path().map(Path::to_path_buf),
                "wrapper path must mirror composer for source={source:?}",
            );
        } else {
            assert!(
                !transitioned,
                "wrapper must return false when composer returns None for source={source:?}",
            );
            assert_eq!(
                std::mem::discriminant::<AppState>(&state),
                std::mem::discriminant::<AppState>(source),
                "wrapper must leave variant unchanged when composer returns None for source={source:?}",
            );
            assert_eq!(
                state.path().map(Path::to_path_buf),
                source.path().map(Path::to_path_buf),
                "wrapper must leave path unchanged when composer returns None for source={source:?}",
            );
        }
    }
}

// ---------------------------------------------------------------------------
// apply_submit_rename_inplace — `AppModel::update` mut-state wrapper
// ---------------------------------------------------------------------------
//
// Symmetric partner of `apply_submit_unlock_inplace` for the rename
// path: where `apply_submit_unlock_inplace` covers `Locked →
// UnlockedBusy` (the open worker is about to compute the `(Vault,
// Store)` pair), `apply_submit_rename_inplace` covers `Unlocked →
// UnlockedBusy` (the rename worker takes the already-decrypted pair
// through `Vault::mutate_and_save`). Both are thin mut-reference
// wrappers over their matching `submit_*_app_state` composer so
// `AppModel::update`'s `RenameDialogOutput::SubmitLabel` handler
// does not have to manage the take-and-restore dance around the
// composer's `Option<AppState>` return — the wrapper keeps the
// side-effect decision unit-testable here without spinning up GTK /
// libadwaita.

#[test]
fn apply_submit_rename_inplace_from_unlocked_mutates_to_unlocked_busy_and_returns_true() {
    // Happy path: `AppModel::update` mutates `self.state` in place
    // via the helper when `RenameDialogOutput::SubmitLabel` arrives
    // from `AppState::Unlocked`. The resolved path is preserved
    // verbatim so the rest of `AppModel` (account list, kebab menu,
    // dialog chrome) still names the same vault destination. The
    // `true` return signals that the state actually transitioned so
    // the caller can spawn the `gio::spawn_blocking
    // Vault::mutate_and_save(|v| v.rename(...))` worker — the
    // `false` arm of the API is the defensive no-op for stray
    // dispatches.
    let path = vault_path();
    let mut state = AppState::Unlocked { path: path.clone() };
    let transitioned = apply_submit_rename_inplace(&mut state);
    assert!(
        transitioned,
        "apply_submit_rename_inplace must return true on the Unlocked → UnlockedBusy transition",
    );
    assert!(matches!(state, AppState::UnlockedBusy { .. }));
    assert_path_eq(&state, &path);
}

#[test]
fn apply_submit_rename_inplace_from_non_unlocked_leaves_state_unchanged_and_returns_false() {
    // Defensive: a stray `SubmitLabel` dispatch from any non-
    // `Unlocked` source is a no-op. The wrapped state must survive
    // the call byte-for-byte so `AppModel::update` cannot
    // accidentally clobber an idle state (`Missing` / `Locked` /
    // `UnlockedBusy` / `StartupError`) with a phantom
    // `UnlockedBusy`. The `false` return tells the caller not to
    // spawn the rename worker.
    let path = vault_path();
    let sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::UnlockedBusy { path: path.clone() },
        decide_state_from_inspect(&path, Err(invalid_header_err()))
            .expect("inspect Err yields StartupError state"),
    ];
    for source in sources {
        let original_discriminant = std::mem::discriminant::<AppState>(&source);
        let original_path = source.path().map(Path::to_path_buf);
        let mut state = source.clone();
        let transitioned = apply_submit_rename_inplace(&mut state);
        assert!(
            !transitioned,
            "apply_submit_rename_inplace must return false for non-Unlocked source={source:?}",
        );
        assert_eq!(
            std::mem::discriminant::<AppState>(&state),
            original_discriminant,
            "apply_submit_rename_inplace must leave variant unchanged for source={source:?}",
        );
        assert_eq!(
            state.path().map(Path::to_path_buf),
            original_path,
            "apply_submit_rename_inplace must leave path unchanged for source={source:?}",
        );
    }
}

#[test]
fn apply_submit_rename_inplace_mirrors_submit_rename_app_state_for_every_variant() {
    // Cross-check: the wrapper must mirror `submit_rename_app_state`
    // exactly. It is a name-the-call-site wrapper, not a
    // re-derivation — the `true` / `false` partition matches the
    // `Some` / `None` partition of the composer, and the resulting
    // state on `true` matches the `Some(_)` variant + path the
    // composer reports. This test pins that contract so the wrapper
    // can't drift away from `submit_rename_app_state` without
    // breaking here first.
    let path = vault_path();
    let sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
        AppState::UnlockedBusy { path: path.clone() },
        decide_state_from_inspect(&path, Err(invalid_header_err()))
            .expect("inspect Err yields StartupError state"),
    ];
    for source in &sources {
        let composed = submit_rename_app_state(source);
        let mut state = source.clone();
        let transitioned = apply_submit_rename_inplace(&mut state);
        if let Some(expected) = composed {
            assert!(
                transitioned,
                "wrapper must return true when composer returns Some for source={source:?}",
            );
            assert_eq!(
                std::mem::discriminant::<AppState>(&state),
                std::mem::discriminant::<AppState>(&expected),
                "wrapper variant must mirror composer for source={source:?}",
            );
            assert_eq!(
                state.path().map(Path::to_path_buf),
                expected.path().map(Path::to_path_buf),
                "wrapper path must mirror composer for source={source:?}",
            );
        } else {
            assert!(
                !transitioned,
                "wrapper must return false when composer returns None for source={source:?}",
            );
            assert_eq!(
                std::mem::discriminant::<AppState>(&state),
                std::mem::discriminant::<AppState>(source),
                "wrapper must leave variant unchanged when composer returns None for source={source:?}",
            );
            assert_eq!(
                state.path().map(Path::to_path_buf),
                source.path().map(Path::to_path_buf),
                "wrapper must leave path unchanged when composer returns None for source={source:?}",
            );
        }
    }
}

// ---------------------------------------------------------------------------
// apply_submit_add_inplace — `AppModel::update` mut-state wrapper
// ---------------------------------------------------------------------------
//
// Symmetric partner of `apply_submit_rename_inplace` for the add
// path: both cover `Unlocked → UnlockedBusy` (the worker takes the
// already-decrypted `(Vault, Store)` pair through
// `Vault::mutate_and_save`), but they bridge different dispatch
// origins. `apply_submit_rename_inplace` fires from
// `RenameDialogOutput::SubmitLabel`; `apply_submit_add_inplace`
// fires from `AddAccountOutput::Submit{Manual,Uri}`. Both are thin
// mut-reference wrappers over their matching `submit_*_app_state`
// composer so `AppModel::update`'s submit handler does not have to
// manage the take-and-restore dance around the composer's
// `Option<AppState>` return — the wrapper keeps the side-effect
// decision unit-testable here without spinning up GTK / libadwaita.

#[test]
fn apply_submit_add_inplace_from_unlocked_mutates_to_unlocked_busy_and_returns_true() {
    // Happy path: `AppModel::update` mutates `self.state` in place
    // via the helper when `AddAccountOutput::Submit{Manual,Uri}`
    // arrives from `AppState::Unlocked`. The resolved path is
    // preserved verbatim so the rest of `AppModel` (account list,
    // header bar, dialog chrome) still names the same vault
    // destination. The `true` return signals that the state actually
    // transitioned so the caller can spawn the `gio::spawn_blocking
    // Vault::mutate_and_save(|v| v.add(account))` worker — the
    // `false` arm of the API is the defensive no-op for stray
    // dispatches.
    let path = vault_path();
    let mut state = AppState::Unlocked { path: path.clone() };
    let transitioned = apply_submit_add_inplace(&mut state);
    assert!(
        transitioned,
        "apply_submit_add_inplace must return true on the Unlocked → UnlockedBusy transition",
    );
    assert!(matches!(state, AppState::UnlockedBusy { .. }));
    assert_path_eq(&state, &path);
}

#[test]
fn apply_submit_add_inplace_from_non_unlocked_leaves_state_unchanged_and_returns_false() {
    // Defensive: a stray `Submit{Manual,Uri}` dispatch from any non-
    // `Unlocked` source is a no-op. The wrapped state must survive
    // the call byte-for-byte so `AppModel::update` cannot
    // accidentally clobber an idle state (`Missing` / `Locked` /
    // `UnlockedBusy` / `StartupError`) with a phantom
    // `UnlockedBusy`. The `false` return tells the caller not to
    // spawn the add worker.
    let path = vault_path();
    let sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::UnlockedBusy { path: path.clone() },
        decide_state_from_inspect(&path, Err(invalid_header_err()))
            .expect("inspect Err yields StartupError state"),
    ];
    for source in sources {
        let original_discriminant = std::mem::discriminant::<AppState>(&source);
        let original_path = source.path().map(Path::to_path_buf);
        let mut state = source.clone();
        let transitioned = apply_submit_add_inplace(&mut state);
        assert!(
            !transitioned,
            "apply_submit_add_inplace must return false for non-Unlocked source={source:?}",
        );
        assert_eq!(
            std::mem::discriminant::<AppState>(&state),
            original_discriminant,
            "apply_submit_add_inplace must leave variant unchanged for source={source:?}",
        );
        assert_eq!(
            state.path().map(Path::to_path_buf),
            original_path,
            "apply_submit_add_inplace must leave path unchanged for source={source:?}",
        );
    }
}

#[test]
fn apply_submit_add_inplace_mirrors_submit_add_app_state_for_every_variant() {
    // Cross-check: the wrapper must mirror `submit_add_app_state`
    // exactly. It is a name-the-call-site wrapper, not a
    // re-derivation — the `true` / `false` partition matches the
    // `Some` / `None` partition of the composer, and the resulting
    // state on `true` matches the `Some(_)` variant + path the
    // composer reports. This test pins that contract so the wrapper
    // can't drift away from `submit_add_app_state` without breaking
    // here first.
    let path = vault_path();
    let sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
        AppState::UnlockedBusy { path: path.clone() },
        decide_state_from_inspect(&path, Err(invalid_header_err()))
            .expect("inspect Err yields StartupError state"),
    ];
    for source in &sources {
        let composed = submit_add_app_state(source);
        let mut state = source.clone();
        let transitioned = apply_submit_add_inplace(&mut state);
        if let Some(expected) = composed {
            assert!(
                transitioned,
                "wrapper must return true when composer returns Some for source={source:?}",
            );
            assert_eq!(
                std::mem::discriminant::<AppState>(&state),
                std::mem::discriminant::<AppState>(&expected),
                "wrapper variant must mirror composer for source={source:?}",
            );
            assert_eq!(
                state.path().map(Path::to_path_buf),
                expected.path().map(Path::to_path_buf),
                "wrapper path must mirror composer for source={source:?}",
            );
        } else {
            assert!(
                !transitioned,
                "wrapper must return false when composer returns None for source={source:?}",
            );
            assert_eq!(
                std::mem::discriminant::<AppState>(&state),
                std::mem::discriminant::<AppState>(source),
                "wrapper must leave variant unchanged when composer returns None for source={source:?}",
            );
            assert_eq!(
                state.path().map(Path::to_path_buf),
                source.path().map(Path::to_path_buf),
                "wrapper must leave path unchanged when composer returns None for source={source:?}",
            );
        }
    }
}

#[test]
fn apply_submit_add_inplace_agrees_with_apply_submit_rename_inplace() {
    // Both `apply_submit_add_inplace` and `apply_submit_rename_inplace`
    // bridge `Unlocked → UnlockedBusy` via the same
    // `AppState::enter_busy` contract — they only differ by the
    // dispatch origin (manual/URI submit vs. label submit). For every
    // possible `AppState` variant the `true`/`false` return and the
    // resulting state's variant + path must match. Pinning the
    // agreement here ensures the two helpers can't silently diverge
    // on the busy-gate transition even though they live in
    // independent call sites.
    let path = vault_path();
    let sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
        AppState::UnlockedBusy { path: path.clone() },
        decide_state_from_inspect(&path, Err(invalid_header_err()))
            .expect("inspect Err yields StartupError state"),
    ];
    for source in &sources {
        let mut add_state = source.clone();
        let mut rename_state = source.clone();
        let add_transitioned = apply_submit_add_inplace(&mut add_state);
        let rename_transitioned = apply_submit_rename_inplace(&mut rename_state);
        assert_eq!(
            add_transitioned, rename_transitioned,
            "apply_submit_add_inplace and apply_submit_rename_inplace must agree on true/false \
             for source={source:?}",
        );
        assert_eq!(
            std::mem::discriminant::<AppState>(&add_state),
            std::mem::discriminant::<AppState>(&rename_state),
            "apply_submit_add_inplace and apply_submit_rename_inplace must produce the same \
             variant for source={source:?}",
        );
        assert_eq!(
            add_state.path().map(Path::to_path_buf),
            rename_state.path().map(Path::to_path_buf),
            "apply_submit_add_inplace and apply_submit_rename_inplace must produce the same \
             path for source={source:?}",
        );
    }
}

// ---------------------------------------------------------------------------
// apply_add_vault_install_inplace — `AppModel::vault` mut-slot wrapper
// ---------------------------------------------------------------------------
//
// Symmetric partner of `apply_rename_vault_install_inplace` for the
// add path. `AddWorkerCompletion` carries the live `(Vault, Store)`
// pair *unconditionally* (every effect branch — `Success`,
// `save_durability_unconfirmed`, `save_not_committed`, and the
// defensive `validation_error` / `invalid_state` / `io_error`
// projections — comes back with the same pair because
// `Vault::mutate_and_save` is the authoritative rollback /
// durability source per DESIGN.md §4.3), so this wrapper takes the
// pair by value rather than the `Option<(Vault, Store)>` shape
// `apply_unlock_vault_install_inplace` uses. The
// `AppMsg::AddWorkerCompleted` handler that lands in a follow-up
// commit will call it next to `apply_add_dispatch_inplace` the same
// way the rename dispatch installs the pair next to
// `apply_rename_dispatch_inplace`.

#[test]
fn apply_add_vault_install_inplace_writes_pair_into_empty_slot() {
    // Defensive: the add flow enters with `AppModel::vault =
    // Some(_)` (the dispatch comes from `Unlocked`), but a stray
    // dispatch from a non-`Unlocked` source state could leave the
    // slot empty when the completion arrives. The wrapper must still
    // install the pair — `Vault::mutate_and_save` returned an
    // authoritative `(Vault, Store)` and silently dropping it on the
    // floor would leak the unlocked state.
    let (_tempdir, _path, pair) = fresh_plaintext_vault_pair();
    let mut slot: Option<(paladin_core::Vault, paladin_core::Store)> = None;
    apply_add_vault_install_inplace(&mut slot, pair);
    assert!(
        slot.is_some(),
        "apply_add_vault_install_inplace must install the pair into an empty slot",
    );
}

#[test]
fn apply_add_vault_install_inplace_replaces_existing_slot() {
    // Happy path: add dispatch enters with `AppModel::vault =
    // Some(pair_a)` from the pre-`UnlockedBusy` snapshot. The worker
    // takes the pair out, runs `mutate_and_save`, and returns a
    // fresh `(Vault, Store)` pair (`pair_b`). The wrapper must
    // overwrite `pair_a` with `pair_b` so the live slot reflects
    // the post-save state — `Vault::mutate_and_save` is the
    // authoritative rollback / durability source, so the returned
    // pair is the only correct slot value regardless of the typed
    // effect.
    let (_tempdir_a, _path_a, pair_a) = fresh_plaintext_vault_pair();
    let (_tempdir_b, _path_b, pair_b) = fresh_plaintext_vault_pair();
    let mut slot = Some(pair_a);
    apply_add_vault_install_inplace(&mut slot, pair_b);
    assert!(
        slot.is_some(),
        "apply_add_vault_install_inplace must leave the slot filled after a replacement",
    );
}

#[test]
fn apply_add_vault_install_inplace_consumes_run_add_worker_completion_pair() {
    // Cross-check: the wrapper must round-trip the unconditional
    // `(Vault, Store)` pair carried by `AddWorkerCompletion`
    // regardless of the `AddWorkerEffect` variant. The add worker
    // always returns the pair — `Success`, durability-unconfirmed
    // warnings, and `save_not_committed` rollbacks all come back
    // with the same shape — so the wrapper is contract-identical
    // across every effect branch. Pinning this here means the
    // wrapper can't drift away from `run_add_worker`'s pair
    // contract without breaking here first.
    use paladin_core::{validate_manual, AccountInput, AccountKindInput, Algorithm, IconHintInput};
    use secrecy::SecretString;

    let (_tempdir, _vault_path, pair) = fresh_plaintext_vault_pair();
    let (vault, store) = pair;
    let input = AccountInput {
        label: "label".to_string(),
        issuer: Some("issuer".to_string()),
        secret: SecretString::from("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Totp,
        period_secs: None,
        counter: None,
        icon_hint: IconHintInput::Default,
    };
    let validated =
        validate_manual(input, SystemTime::UNIX_EPOCH).expect("totp account input validates");

    let worker_input = AddWorkerInput {
        vault,
        store,
        account: validated.account,
    };
    let completion = paladin_gtk::add_account::run_add_worker(worker_input);

    let mut slot: Option<(paladin_core::Vault, paladin_core::Store)> = None;
    apply_add_vault_install_inplace(&mut slot, (completion.vault, completion.store));
    assert!(
        slot.is_some(),
        "run_add_worker completion pair must install (add always returns the pair)",
    );
    let (installed_vault, _installed_store) = slot.expect("installed pair");
    assert_eq!(
        installed_vault.accounts().len(),
        1,
        "installed vault must reflect the post-save state from run_add_worker — \
         the just-added account should be present after the wrapper installs the pair",
    );
}

// ---------------------------------------------------------------------------
// add_final_app_state — unified state-transition composer
// ---------------------------------------------------------------------------
//
// Symmetric partner of `rename_final_app_state` for the add path.
// Every `AddWorkerEffect` variant — `Success { account_id }` and
// `Failure(AddPostEffectOutcome::{Inline, KeepWithWarning})` — lands
// on the same `UnlockedBusy → Unlocked` transition via
// `AppState::leave_busy`. The dialog drop / inline-message decisions
// split off the effect in sibling composers in follow-up commits;
// this composer owns only the state-machine roll-back.
//
// The `None` return is reserved for the defensive case where the
// completion arrives but `current` is not `UnlockedBusy` — a stray
// call from an unexpected source state that should not silently
// install a phantom `Unlocked` over another idle state.
//
// `AddPostEffectOutcome` only has two variants
// (`Inline(InlineError)` for `save_not_committed` / `io_error` /
// defensive `validation_error` / `invalid_state`, and
// `KeepWithWarning(InlineWarning)` for `save_durability_unconfirmed`)
// — narrower than the rename outcome's three-way split because the
// add path has no equivalent of `RestorePrior` / `KeepNewWithWarning`
// since there is no pre-existing field to roll back to.

#[test]
fn add_final_app_state_success_rolls_back_to_unlocked_preserving_path() {
    use paladin_core::AccountId;
    use paladin_gtk::add_account::AddWorkerEffect;
    use paladin_gtk::app::state::add_final_app_state;

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let effect = AddWorkerEffect::Success {
        account_id: AccountId::new(),
    };
    let next = add_final_app_state(&busy, &effect)
        .expect("success outcome rolls back UnlockedBusy → Unlocked");
    assert!(matches!(next, AppState::Unlocked { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn add_final_app_state_failure_inline_rolls_back_to_unlocked_preserving_path() {
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddPostEffectOutcome, AddWorkerEffect,
    };
    use paladin_gtk::app::state::add_final_app_state;

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let outcome = classify_add_post_effect_error(&err);
    assert!(
        matches!(outcome, AddPostEffectOutcome::Inline(_)),
        "save_not_committed routes to Inline (pinned in add_account tests)",
    );
    let effect = AddWorkerEffect::Failure(outcome);
    let next = add_final_app_state(&busy, &effect)
        .expect("Inline failure rolls back UnlockedBusy → Unlocked (dialog stays inline)");
    assert!(matches!(next, AppState::Unlocked { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn add_final_app_state_failure_keep_with_warning_rolls_back_to_unlocked_preserving_path() {
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddPostEffectOutcome, AddWorkerEffect,
    };
    use paladin_gtk::app::state::add_final_app_state;

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = PaladinError::SaveDurabilityUnconfirmed;
    let outcome = classify_add_post_effect_error(&err);
    assert!(
        matches!(outcome, AddPostEffectOutcome::KeepWithWarning(_)),
        "save_durability_unconfirmed routes to KeepWithWarning",
    );
    let effect = AddWorkerEffect::Failure(outcome);
    let next = add_final_app_state(&busy, &effect).expect(
        "KeepWithWarning failure rolls back UnlockedBusy → Unlocked (dialog keeps warning)",
    );
    assert!(matches!(next, AppState::Unlocked { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn add_final_app_state_failure_defensive_inline_rolls_back_to_unlocked_preserving_path() {
    // Defensive: an `invalid_state` would only fire if the
    // `Vault::mutate_and_save` closure observed an unexpected
    // post-condition (e.g. the just-added account disappeared mid-
    // flight). `classify_add_post_effect_error` routes it to `Inline`.
    // Pin the same `UnlockedBusy → Unlocked` rollback for the
    // defensive branch.
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddPostEffectOutcome, AddWorkerEffect,
    };
    use paladin_gtk::app::state::add_final_app_state;

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = PaladinError::InvalidState {
        operation: "add",
        state: "account_not_found",
    };
    let outcome = classify_add_post_effect_error(&err);
    assert!(
        matches!(outcome, AddPostEffectOutcome::Inline(_)),
        "defensive invalid_state routes to Inline",
    );
    let effect = AddWorkerEffect::Failure(outcome);
    let next = add_final_app_state(&busy, &effect)
        .expect("defensive Inline failure rolls back UnlockedBusy → Unlocked");
    assert!(matches!(next, AppState::Unlocked { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn add_final_app_state_from_non_unlocked_busy_returns_none() {
    // Defensive: a stray completion arriving while `current` is not
    // `UnlockedBusy` must not silently install a phantom `Unlocked`
    // transition over another idle state. The composer mirrors the
    // `AppState::leave_busy` contract and returns `None` for every
    // non-`UnlockedBusy` source. Pinned across every typed effect so
    // the defensive arm cannot drift with the effect routing.
    use paladin_core::AccountId;
    use paladin_gtk::add_account::{classify_add_post_effect_error, AddWorkerEffect};
    use paladin_gtk::app::state::add_final_app_state;

    let path = vault_path();
    let effects = [
        AddWorkerEffect::Success {
            account_id: AccountId::new(),
        },
        AddWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::SaveNotCommitted {
                committed: false,
                backup_path: None,
            },
        )),
        AddWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::SaveDurabilityUnconfirmed,
        )),
        AddWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::InvalidState {
                operation: "add",
                state: "account_not_found",
            },
        )),
    ];
    let sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
        decide_state_from_inspect(&path, Err(invalid_header_err()))
            .expect("inspect Err yields StartupError state"),
    ];
    for effect in &effects {
        for source in &sources {
            assert!(
                add_final_app_state(source, effect).is_none(),
                "add_final_app_state must return None for non-UnlockedBusy source={source:?} effect={effect:?}",
            );
        }
    }
}

#[test]
fn add_final_app_state_mirrors_leave_busy_for_every_variant() {
    // Cross-check: the composer is a name-the-call-site wrapper over
    // `AppState::leave_busy`, not a re-derivation. The `Some` /
    // `None` partition across source states must mirror `leave_busy`
    // byte-for-byte (and the result on `Some` must match
    // `leave_busy`'s `Unlocked { path }` projection) so the wrapper
    // can't drift away from the underlying method without breaking
    // here first. Pinned across every typed effect because the
    // composer ignores `effect` for the state decision.
    use paladin_core::AccountId;
    use paladin_gtk::add_account::{classify_add_post_effect_error, AddWorkerEffect};
    use paladin_gtk::app::state::add_final_app_state;

    let path = vault_path();
    let effects = [
        AddWorkerEffect::Success {
            account_id: AccountId::new(),
        },
        AddWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::SaveNotCommitted {
                committed: true,
                backup_path: None,
            },
        )),
        AddWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::SaveDurabilityUnconfirmed,
        )),
        AddWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::InvalidState {
                operation: "add",
                state: "account_not_found",
            },
        )),
    ];
    let sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
        AppState::UnlockedBusy { path: path.clone() },
        decide_state_from_inspect(&path, Err(invalid_header_err()))
            .expect("inspect Err yields StartupError state"),
    ];
    for effect in &effects {
        for source in &sources {
            let composed = add_final_app_state(source, effect);
            let direct = source.clone().leave_busy();
            match (&composed, &direct) {
                (Some(a), Some(b)) => {
                    assert_eq!(
                        std::mem::discriminant::<AppState>(a),
                        std::mem::discriminant::<AppState>(b),
                        "wrapper variant must mirror leave_busy for source={source:?} effect={effect:?}",
                    );
                    assert_eq!(
                        a.path().map(Path::to_path_buf),
                        b.path().map(Path::to_path_buf),
                        "wrapper path must mirror leave_busy for source={source:?} effect={effect:?}",
                    );
                }
                (None, None) => {}
                _ => panic!(
                    "wrapper / leave_busy Some/None partition diverged for source={source:?} effect={effect:?}: composed={composed:?} direct={direct:?}",
                ),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// apply_unlock_dispatch_inplace — `AppModel::update` mut-state wrapper
// ---------------------------------------------------------------------------
//
// `compose_unlock_dispatch(&AppState, &UnlockWorkerEffect) -> UnlockDispatch`
// bundles the three worker-completion decisions (`app_state`,
// `dialog_msg`, `drop_dialog`) so `AppModel::update` can apply the
// worker outcome in a single shot. The wrapper here lets the
// `AppMsg::UnlockWorkerCompleted` handler install the new
// `dispatch.app_state` against the cached `AppState` in place,
// mirroring `apply_submit_unlock_inplace`'s contract for the entry
// transition. The remaining `dialog_msg` and `drop_dialog` projections
// drive widget-side work in the handler and are not the wrapper's
// concern.

#[test]
fn apply_unlock_dispatch_inplace_success_replaces_with_unlocked_and_returns_true() {
    // Worker reported `Ok((Vault, Store))`: `compose_unlock_dispatch`
    // carries `Some(Unlocked(path))` in `app_state`. The wrapper
    // installs the replacement against the cached `UnlockedBusy`
    // state and returns `true` so `AppModel::update` can release the
    // busy gate and proceed to mount `AccountListComponent`.
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let effect = route_unlock_worker_outcome(&path, Ok(()));
    let dispatch = compose_unlock_dispatch(&busy, &effect);
    let mut state = busy.clone();
    let transitioned = apply_unlock_dispatch_inplace(&mut state, &dispatch);
    assert!(
        transitioned,
        "apply_unlock_dispatch_inplace must return true on the Success replacement",
    );
    assert!(
        matches!(state, AppState::Unlocked { .. }),
        "Success replacement target must be Unlocked, got {state:?}",
    );
    assert_path_eq(&state, &path);
}

#[test]
fn apply_unlock_dispatch_inplace_startup_failure_replaces_with_startup_error_and_returns_true() {
    // Worker reported a non-passphrase open failure
    // (`unsafe_permissions`): `compose_unlock_dispatch` carries
    // `Some(StartupError(path))` in `app_state`. The wrapper installs
    // the replacement against the cached `UnlockedBusy` state and
    // returns `true` so `AppModel::update` can drop the
    // `UnlockDialogComponent` and surface `StartupErrorComponent`.
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = unsafe_perms_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    let dispatch = compose_unlock_dispatch(&busy, &effect);
    let mut state = busy.clone();
    let transitioned = apply_unlock_dispatch_inplace(&mut state, &dispatch);
    assert!(
        transitioned,
        "apply_unlock_dispatch_inplace must return true on the startup-routed failure replacement",
    );
    assert!(
        matches!(state, AppState::StartupError { .. }),
        "startup-routed failure target must be StartupError, got {state:?}",
    );
    assert_eq!(
        state.path().map(Path::to_path_buf),
        Some(path),
        "startup-routed failure preserves the resolved path",
    );
}

#[test]
fn apply_unlock_dispatch_inplace_inline_failure_rolls_back_to_locked_and_returns_true() {
    // Worker reported an inline open failure (`decrypt_failed`):
    // `compose_unlock_dispatch` carries `Some(Locked(path))` in
    // `app_state` (the rollback) alongside the inline message.
    // The wrapper installs the rollback against the cached
    // `UnlockedBusy` state and returns `true` so `AppModel::update`
    // releases the busy gate and lets the still-mounted dialog
    // accept a fresh passphrase entry.
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = decrypt_failed_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    let dispatch = compose_unlock_dispatch(&busy, &effect);
    let mut state = busy.clone();
    let transitioned = apply_unlock_dispatch_inplace(&mut state, &dispatch);
    assert!(
        transitioned,
        "apply_unlock_dispatch_inplace must return true on the inline rollback",
    );
    assert!(
        matches!(state, AppState::Locked { .. }),
        "inline rollback target must be Locked, got {state:?}",
    );
    assert_path_eq(&state, &path);
}

#[test]
fn apply_unlock_dispatch_inplace_inline_from_non_unlocked_busy_leaves_state_unchanged_and_returns_false(
) {
    // Defensive: when the worker reports an inline failure but the
    // cached state is not `UnlockedBusy` (a stray dispatch from any
    // other source), `compose_unlock_dispatch` reports `app_state =
    // None` to refuse a phantom `Locked` transition. The wrapper must
    // leave the cached state untouched byte-for-byte and return
    // `false` so `AppModel::update` does not clobber an idle state
    // (`Missing` / `Locked` / `Unlocked`) with a phantom rollback.
    let path = vault_path();
    let err = decrypt_failed_err();
    let effect = route_unlock_worker_outcome(&path, Err(&err));
    let invalid_sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
    ];
    for source in invalid_sources {
        let dispatch = compose_unlock_dispatch(&source, &effect);
        assert!(
            dispatch.app_state.is_none(),
            "fixture invariant: inline branch from non-UnlockedBusy must carry app_state=None",
        );
        let original_discriminant = std::mem::discriminant::<AppState>(&source);
        let original_path = source.path().map(Path::to_path_buf);
        let mut state = source.clone();
        let transitioned = apply_unlock_dispatch_inplace(&mut state, &dispatch);
        assert!(
            !transitioned,
            "apply_unlock_dispatch_inplace must return false when dispatch.app_state is None \
             for source={source:?}",
        );
        assert_eq!(
            std::mem::discriminant::<AppState>(&state),
            original_discriminant,
            "wrapper must leave variant unchanged when dispatch.app_state is None \
             for source={source:?}",
        );
        assert_eq!(
            state.path().map(Path::to_path_buf),
            original_path,
            "wrapper must leave path unchanged when dispatch.app_state is None \
             for source={source:?}",
        );
    }
}

#[test]
fn apply_unlock_dispatch_inplace_mirrors_compose_unlock_dispatch_for_every_effect() {
    // Cross-check: the wrapper must mirror the
    // `compose_unlock_dispatch.app_state` Some/None partition exactly
    // — it is a name-the-call-site wrapper, not a re-derivation. The
    // resulting state on `true` matches the `Some(_)` variant + path
    // the composer reports. Pinning this contract here means the
    // wrapper can't drift away from the composer without breaking
    // here first. The cached source is always `UnlockedBusy(path)`
    // since that is the only state `AppModel::update` ever reaches
    // when the worker returns.
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let effects = [
        route_unlock_worker_outcome(&path, Ok(())),
        route_unlock_worker_outcome(&path, Err(&decrypt_failed_err())),
        route_unlock_worker_outcome(&path, Err(&invalid_passphrase_empty_err())),
        route_unlock_worker_outcome(&path, Err(&unsafe_perms_err())),
        route_unlock_worker_outcome(&path, Err(&io_err())),
        route_unlock_worker_outcome(&path, Err(&wrong_vault_lock_err())),
        route_unlock_worker_outcome(&path, Err(&invalid_header_err())),
        route_unlock_worker_outcome(&path, Err(&invalid_payload_err())),
        route_unlock_worker_outcome(&path, Err(&unsupported_format_version_err())),
        route_unlock_worker_outcome(&path, Err(&kdf_oob_err())),
    ];
    for effect in &effects {
        let dispatch = compose_unlock_dispatch(&busy, effect);
        let mut state = busy.clone();
        let transitioned = apply_unlock_dispatch_inplace(&mut state, &dispatch);
        if let Some(expected) = dispatch.app_state.as_ref() {
            assert!(
                transitioned,
                "wrapper must return true when dispatch.app_state is Some for effect={effect:?}",
            );
            assert_eq!(
                std::mem::discriminant::<AppState>(&state),
                std::mem::discriminant::<AppState>(expected),
                "wrapper variant must mirror composer for effect={effect:?}",
            );
            assert_eq!(
                state.path().map(Path::to_path_buf),
                expected.path().map(Path::to_path_buf),
                "wrapper path must mirror composer for effect={effect:?}",
            );
        } else {
            assert!(
                !transitioned,
                "wrapper must return false when dispatch.app_state is None for effect={effect:?}",
            );
            assert_eq!(
                std::mem::discriminant::<AppState>(&state),
                std::mem::discriminant::<AppState>(&busy),
                "wrapper must leave variant unchanged when dispatch.app_state is None \
                 for effect={effect:?}",
            );
            assert_eq!(
                state.path().map(Path::to_path_buf),
                busy.path().map(Path::to_path_buf),
                "wrapper must leave path unchanged when dispatch.app_state is None \
                 for effect={effect:?}",
            );
        }
    }
}

// ---------------------------------------------------------------------------
// compose_unlock_worker_input — pre-worker `(path, VaultLock)` bundler
// ---------------------------------------------------------------------------
//
// Symmetric partner of `submit_unlock_app_state`: that composer owns
// the entry-side `Locked → UnlockedBusy` state transition,
// `compose_unlock_worker_input` owns the entry-side bundling of the
// resolved vault path with the typed `VaultLock` forwarded from
// `UnlockDialogOutput::SubmitLock`. The bundled `UnlockWorkerInput` is
// the value `AppModel::update` moves into the `gio::spawn_blocking
// paladin_core::open` worker closure. Both composers inspect `current`
// before the transition so the path is captured before
// `AppState::enter_unlocking_busy` consumes the `Locked` variant; both
// return `None` for every non-`Locked` source so a stray `SubmitLock`
// is a benign no-op for the worker spawn just as it is for the state
// machine.

#[test]
fn compose_unlock_worker_input_from_locked_bundles_path_and_plaintext_lock() {
    // Happy path: `AppModel::update` receives `SubmitLock(VaultLock)`
    // while the model is `Locked(path)`. The composer must hand the
    // worker a `(path, VaultLock)` pair that names the same
    // destination the dialog is currently showing. The plaintext
    // variant has no secrets to redact, so the lock is preserved
    // verbatim — `matches!` is enough to pin the variant.
    let path = vault_path();
    let locked = AppState::Locked { path: path.clone() };
    let input = compose_unlock_worker_input(&locked, VaultLock::Plaintext)
        .expect("Locked must produce a worker input");
    assert_eq!(input.path, path);
    assert!(matches!(input.lock, VaultLock::Plaintext));
}

#[test]
fn compose_unlock_worker_input_preserves_encrypted_passphrase_through_bundle() {
    // Encrypted variant: the `SecretString` carried by
    // `VaultLock::Encrypted` must move (not clone) through the
    // composer so zeroize-on-drop semantics stay intact across the
    // `gio::spawn_blocking` boundary. `expose_secret` is the only way
    // to compare the inner string in a test; production code never
    // calls it (the worker hands the lock straight to
    // `paladin_core::open`).
    use secrecy::{ExposeSecret, SecretString};
    let path = vault_path();
    let locked = AppState::Locked { path: path.clone() };
    let lock = VaultLock::Encrypted(SecretString::from("hunter2".to_string()));
    let input =
        compose_unlock_worker_input(&locked, lock).expect("Locked must produce a worker input");
    assert_eq!(input.path, path);
    match input.lock {
        VaultLock::Encrypted(pp) => assert_eq!(pp.expose_secret(), "hunter2"),
        VaultLock::Plaintext => panic!("encrypted lock must be preserved verbatim"),
        _ => panic!("unexpected VaultLock variant"),
    }
}

#[test]
fn compose_unlock_worker_input_from_non_locked_returns_none() {
    // Defensive: a stray `SubmitLock` dispatch from any source state
    // other than `Locked` is a no-op for the worker spawn just as it
    // is for the state machine. Missing has no encrypted vault to
    // open, Unlocked / UnlockedBusy already own a different busy
    // window through `enter_busy`, and StartupError is the
    // non-mutating surface. Returning `None` mirrors
    // `submit_unlock_app_state`'s refusal contract so the two
    // composers agree on every source variant — see the cross-check
    // test below.
    let path = vault_path();
    assert!(compose_unlock_worker_input(
        &AppState::Missing { path: path.clone() },
        VaultLock::Plaintext,
    )
    .is_none());
    assert!(compose_unlock_worker_input(
        &AppState::Unlocked { path: path.clone() },
        VaultLock::Plaintext,
    )
    .is_none());
    assert!(compose_unlock_worker_input(
        &AppState::UnlockedBusy { path: path.clone() },
        VaultLock::Plaintext,
    )
    .is_none());
    let startup = decide_state_from_inspect(&path, Err(invalid_header_err()))
        .expect("inspect Err yields StartupError state");
    assert!(compose_unlock_worker_input(&startup, VaultLock::Plaintext).is_none());
}

#[test]
fn compose_unlock_worker_input_mirrors_submit_unlock_app_state_gating() {
    // Cross-check: both entry-side composers — "transition the state"
    // (`submit_unlock_app_state`) and "bundle the worker input"
    // (`compose_unlock_worker_input`) — must agree on the Some/None
    // partition for every source variant. The pair brackets the
    // `gio::spawn_blocking paladin_core::open` worker spawn: if one
    // fires without the other, `AppModel` ends up with a busy gate
    // and no worker, or a spawned worker and no busy gate. Pin the
    // agreement here so neither composer can drift away from
    // `AppState::enter_unlocking_busy`'s `Locked → UnlockedBusy`
    // refusal contract without breaking here first.
    let path = vault_path();
    let sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
        AppState::UnlockedBusy { path: path.clone() },
        decide_state_from_inspect(&path, Err(invalid_header_err()))
            .expect("inspect Err yields StartupError state"),
    ];
    for source in &sources {
        let state_transition = submit_unlock_app_state(source).is_some();
        // Fresh `VaultLock::Plaintext` per call because the helper
        // consumes the lock by value; `Plaintext` is a unit variant
        // so this is free.
        let worker_input = compose_unlock_worker_input(source, VaultLock::Plaintext).is_some();
        assert_eq!(
            state_transition, worker_input,
            "submit_unlock_app_state and compose_unlock_worker_input must agree on Some/None \
             for source={source:?}",
        );
    }
}

// ---------------------------------------------------------------------------
// apply_unlock_vault_install_inplace — `AppModel::vault` mut-slot wrapper
// ---------------------------------------------------------------------------
//
// `route_unlock_open_completion(&Path, Result<(Vault, Store), PaladinError>)
// -> UnlockWorkerCompletion` bundles the worker's pair alongside the
// routed effect: on `Ok(_)` it carries `pair = Some(_)`, on every
// `Err(_)` it carries `pair = None`. The wrapper here lets the
// `AppMsg::UnlockWorkerCompleted` handler install that pair against
// the `AppModel::vault` sibling `Option<(Vault, Store)>` slot in
// place, mirroring `apply_unlock_dispatch_inplace`'s contract for
// the state side. Together the two wrappers absorb the full
// `UnlockWorkerCompletion` without spreading the unpack across
// `AppModel::update`.

#[test]
fn apply_unlock_vault_install_inplace_installs_some_pair_into_empty_slot_and_returns_true() {
    // Happy path: worker returned `Ok(pair)`, the slot was empty
    // (vault was `Locked` entering the flow, so `AppModel::vault`
    // was `None` through `UnlockedBusy`). The wrapper installs the
    // pair and returns `true` so `AppModel::update` can mount
    // `AccountListComponent` against a live vault.
    let (_tempdir, _path, pair) = fresh_plaintext_vault_pair();
    let mut slot: Option<(paladin_core::Vault, paladin_core::Store)> = None;
    let installed = apply_unlock_vault_install_inplace(&mut slot, Some(pair));
    assert!(
        installed,
        "apply_unlock_vault_install_inplace must return true on the Some-pair install",
    );
    assert!(
        slot.is_some(),
        "slot must hold the installed pair after a Some-pair call",
    );
}

#[test]
fn apply_unlock_vault_install_inplace_none_pair_leaves_empty_slot_untouched_and_returns_false() {
    // Every `Err(_)` branch from `route_unlock_open_completion`
    // carries `pair = None`. The wrapper must leave the slot
    // untouched and return `false` so `AppModel::update` does not
    // flip the slot to `Some(_)` on a failure outcome.
    let mut slot: Option<(paladin_core::Vault, paladin_core::Store)> = None;
    let installed = apply_unlock_vault_install_inplace(&mut slot, None);
    assert!(
        !installed,
        "apply_unlock_vault_install_inplace must return false when pair is None",
    );
    assert!(
        slot.is_none(),
        "slot must remain empty when pair is None and slot started empty",
    );
}

#[test]
fn apply_unlock_vault_install_inplace_some_pair_replaces_existing_slot_and_returns_true() {
    // Defensive: although the unlock flow only ever calls this
    // wrapper against an empty slot, the contract for symmetry with
    // every other vault-touching worker (HOTP `next`, add / remove /
    // rename, settings saves, import / export, passphrase
    // transitions) is that an incoming `Some(_)` always overwrites.
    // Those workers take `(Vault, Store)` out into the closure, leave
    // `AppModel::vault` `None` through `UnlockedBusy`, and reinstall
    // a fresh pair on completion — the wrapper must be idempotent
    // against a non-empty slot so a stray double-fire of the install
    // path does not panic or silently no-op.
    let (_tempdir_a, _path_a, pair_a) = fresh_plaintext_vault_pair();
    let (_tempdir_b, _path_b, pair_b) = fresh_plaintext_vault_pair();
    let mut slot = Some(pair_a);
    let installed = apply_unlock_vault_install_inplace(&mut slot, Some(pair_b));
    assert!(
        installed,
        "apply_unlock_vault_install_inplace must return true when replacing an existing pair",
    );
    assert!(slot.is_some(), "slot must remain filled after replacement",);
}

#[test]
fn apply_unlock_vault_install_inplace_none_pair_with_filled_slot_leaves_existing_intact() {
    // Defensive: a `pair = None` call against an already-filled slot
    // (which the unlock flow never produces, but other flows can
    // reach if a stray dispatch arrives before the worker returns)
    // must not clobber the existing pair. The wrapper is a pure
    // no-op on the `None` branch.
    let (_tempdir, _path, pair) = fresh_plaintext_vault_pair();
    let mut slot = Some(pair);
    let installed = apply_unlock_vault_install_inplace(&mut slot, None);
    assert!(
        !installed,
        "apply_unlock_vault_install_inplace must return false when pair is None \
         even against a filled slot",
    );
    assert!(
        slot.is_some(),
        "filled slot must remain filled when pair is None",
    );
}

#[test]
fn apply_unlock_vault_install_inplace_mirrors_route_unlock_open_completion_pair_partition() {
    // Cross-check: the wrapper must mirror the
    // `route_unlock_open_completion.pair` Some/None partition exactly
    // — it is a name-the-call-site wrapper, not a re-derivation.
    // `Ok((Vault, Store))` carries `Some(pair)` and yields `true`;
    // every routed `Err(_)` carries `None` and yields `false`.
    // Pinning this contract here means the wrapper can't drift away
    // from `route_unlock_open_completion` without breaking here
    // first.
    let (_tempdir, ok_path, pair) = fresh_plaintext_vault_pair();
    let completion = paladin_gtk::app::state::route_unlock_open_completion(&ok_path, Ok(pair));
    let mut slot = None;
    let installed = apply_unlock_vault_install_inplace(&mut slot, completion.pair);
    assert!(
        installed,
        "Ok-branch pair must install (mirrors route_unlock_open_completion's pair=Some(_))",
    );
    assert!(slot.is_some(), "Ok-branch must leave slot filled");

    let path = vault_path();
    let errs: [PaladinError; 9] = [
        decrypt_failed_err(),
        invalid_passphrase_empty_err(),
        unsafe_perms_err(),
        io_err(),
        wrong_vault_lock_err(),
        invalid_header_err(),
        invalid_payload_err(),
        unsupported_format_version_err(),
        kdf_oob_err(),
    ];
    for err in errs {
        let err_dbg = format!("{err:?}");
        let completion = paladin_gtk::app::state::route_unlock_open_completion(&path, Err(err));
        let mut slot = None;
        let installed = apply_unlock_vault_install_inplace(&mut slot, completion.pair);
        assert!(
            !installed,
            "Err-branch pair must not install (mirrors route_unlock_open_completion's \
             pair=None) for err={err_dbg}",
        );
        assert!(
            slot.is_none(),
            "Err-branch must leave slot empty for err={err_dbg}",
        );
    }
}

// ---------------------------------------------------------------------------
// apply_rename_vault_install_inplace — `AppModel::vault` mut-slot wrapper
// ---------------------------------------------------------------------------
//
// Symmetric partner of `apply_unlock_vault_install_inplace` for the
// rename path. `RenameWorkerCompletion` carries the live `(Vault,
// Store)` pair *unconditionally* (every effect branch — `Success`,
// `save_durability_unconfirmed`, `save_not_committed`, and the
// defensive `validation_error` / `invalid_state` cases — comes back
// with the same pair because `Vault::mutate_and_save` is the
// authoritative rollback / durability source per DESIGN.md §4.3),
// so this wrapper takes the pair by value rather than the
// `Option<(Vault, Store)>` shape `apply_unlock_vault_install_inplace`
// uses. The `AppMsg::RenameWorkerCompleted` handler that lands in a
// follow-up commit will call it next to `apply_rename_dispatch_inplace`
// the same way the unlock dispatch installs the pair next to
// `apply_unlock_dispatch_inplace`.

#[test]
fn apply_rename_vault_install_inplace_writes_pair_into_empty_slot() {
    // Defensive: the rename flow enters with `AppModel::vault =
    // Some(_)` (the dispatch comes from `Unlocked`), but a stray
    // dispatch from a non-`Unlocked` source state could leave the
    // slot empty when the completion arrives. The wrapper must still
    // install the pair — `Vault::mutate_and_save` returned an
    // authoritative `(Vault, Store)` and silently dropping it on the
    // floor would leak the unlocked state.
    let (_tempdir, _path, pair) = fresh_plaintext_vault_pair();
    let mut slot: Option<(paladin_core::Vault, paladin_core::Store)> = None;
    paladin_gtk::app::state::apply_rename_vault_install_inplace(&mut slot, pair);
    assert!(
        slot.is_some(),
        "apply_rename_vault_install_inplace must install the pair into an empty slot",
    );
}

#[test]
fn apply_rename_vault_install_inplace_replaces_existing_slot() {
    // Happy path: rename dispatch enters with `AppModel::vault =
    // Some(pair_a)` from the pre-`UnlockedBusy` snapshot. The worker
    // takes the pair out, runs `mutate_and_save`, and returns a
    // fresh `(Vault, Store)` pair (`pair_b`). The wrapper must
    // overwrite `pair_a` with `pair_b` so the live slot reflects
    // the post-save state — `Vault::mutate_and_save` is the
    // authoritative rollback / durability source, so the returned
    // pair is the only correct slot value regardless of the typed
    // effect.
    let (_tempdir_a, _path_a, pair_a) = fresh_plaintext_vault_pair();
    let (_tempdir_b, _path_b, pair_b) = fresh_plaintext_vault_pair();
    let mut slot = Some(pair_a);
    paladin_gtk::app::state::apply_rename_vault_install_inplace(&mut slot, pair_b);
    assert!(
        slot.is_some(),
        "apply_rename_vault_install_inplace must leave the slot filled after a replacement",
    );
}

#[test]
fn apply_rename_vault_install_inplace_consumes_run_rename_worker_completion_pair() {
    // Cross-check: the wrapper must round-trip the unconditional
    // `(Vault, Store)` pair carried by `RenameWorkerCompletion`
    // regardless of the `RenameWorkerEffect` variant. The rename
    // worker always returns the pair — `Success`, durability-
    // unconfirmed warnings, and `save_not_committed` rollbacks all
    // come back with the same shape — so the wrapper is contract-
    // identical across every effect branch. Pinning this here means
    // the wrapper can't drift away from `run_rename_worker`'s pair
    // contract without breaking here first.
    use paladin_core::{validate_manual, AccountInput, AccountKindInput, Algorithm, IconHintInput};
    use secrecy::SecretString;

    let (_tempdir, _vault_path, pair) = fresh_plaintext_vault_pair();
    let (mut vault, store) = pair;
    let input = AccountInput {
        label: "label".to_string(),
        issuer: Some("issuer".to_string()),
        secret: SecretString::from("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Totp,
        period_secs: None,
        counter: None,
        icon_hint: IconHintInput::Default,
    };
    let validated =
        validate_manual(input, SystemTime::UNIX_EPOCH).expect("totp account input validates");
    let account_id = vault.add(validated.account);
    vault.save(&store).expect("commit seeded account");

    let worker_input = RenameWorkerInput {
        vault,
        store,
        account_id,
        label: "renamed-label".to_string(),
        now: SystemTime::UNIX_EPOCH,
    };
    let completion = paladin_gtk::rename_dialog::run_rename_worker(worker_input);

    let mut slot: Option<(paladin_core::Vault, paladin_core::Store)> = None;
    paladin_gtk::app::state::apply_rename_vault_install_inplace(
        &mut slot,
        (completion.vault, completion.store),
    );
    assert!(
        slot.is_some(),
        "run_rename_worker completion pair must install (rename always returns the pair)",
    );
    let (installed_vault, _installed_store) = slot.expect("installed pair");
    let renamed = installed_vault
        .accounts()
        .iter()
        .find(|a| a.id() == account_id)
        .expect("renamed account survives the install");
    assert_eq!(
        renamed.label(),
        "renamed-label",
        "post-install vault must reflect the renamed label (mirrors run_rename_worker output)",
    );
}

// ---------------------------------------------------------------------------
// rename_final_app_state — unified state-transition composer
// ---------------------------------------------------------------------------
//
// Symmetric partner of `unlock_final_app_state` for the rename path.
// Where `unlock_final_app_state` has to fan three effect branches
// into two state transitions (success → `Unlocked`, startup-routed
// failure → `StartupError`, inline failure → `Locked` rollback),
// every `RenameWorkerEffect` variant — `Success` and all
// `Failure(RenameErrorOutcome)` projections — lands on the same
// `UnlockedBusy → Unlocked` transition via `AppState::leave_busy`.
// The dialog drop / inline-message decisions split off the effect
// in a sibling composer (`should_drop_rename_dialog_after`); this
// composer owns only the state-machine roll-back.
//
// The `None` return is reserved for the defensive case where the
// completion arrives but `current` is not `UnlockedBusy` — a stray
// call from an unexpected source state that should not silently
// install a phantom `Unlocked` over another idle state.

#[test]
fn rename_final_app_state_success_rolls_back_to_unlocked_preserving_path() {
    use paladin_gtk::app::state::rename_final_app_state;
    use paladin_gtk::rename_dialog::RenameWorkerEffect;

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let effect = RenameWorkerEffect::Success;
    let next = rename_final_app_state(&busy, &effect)
        .expect("success outcome rolls back UnlockedBusy → Unlocked");
    assert!(matches!(next, AppState::Unlocked { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn rename_final_app_state_failure_restore_prior_rolls_back_to_unlocked_preserving_path() {
    use paladin_gtk::app::state::rename_final_app_state;
    use paladin_gtk::rename_dialog::{
        classify_rename_error, RenameErrorOutcome, RenameWorkerEffect,
    };

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let outcome = classify_rename_error(&err);
    assert!(
        matches!(outcome, RenameErrorOutcome::RestorePrior(_)),
        "save_not_committed routes to RestorePrior (pinned in rename_dialog tests)",
    );
    let effect = RenameWorkerEffect::Failure(outcome);
    let next = rename_final_app_state(&busy, &effect)
        .expect("RestorePrior failure rolls back UnlockedBusy → Unlocked (dialog stays inline)");
    assert!(matches!(next, AppState::Unlocked { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn rename_final_app_state_failure_keep_new_with_warning_rolls_back_to_unlocked_preserving_path() {
    use paladin_gtk::app::state::rename_final_app_state;
    use paladin_gtk::rename_dialog::{
        classify_rename_error, RenameErrorOutcome, RenameWorkerEffect,
    };

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = PaladinError::SaveDurabilityUnconfirmed;
    let outcome = classify_rename_error(&err);
    assert!(
        matches!(outcome, RenameErrorOutcome::KeepNewWithWarning(_)),
        "save_durability_unconfirmed routes to KeepNewWithWarning",
    );
    let effect = RenameWorkerEffect::Failure(outcome);
    let next = rename_final_app_state(&busy, &effect).expect(
        "KeepNewWithWarning failure rolls back UnlockedBusy → Unlocked (dialog keeps warning)",
    );
    assert!(matches!(next, AppState::Unlocked { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn rename_final_app_state_failure_inline_error_rolls_back_to_unlocked_preserving_path() {
    use paladin_gtk::app::state::rename_final_app_state;
    use paladin_gtk::rename_dialog::{
        classify_rename_error, RenameErrorOutcome, RenameWorkerEffect,
    };

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    // Defensive: an `invalid_state` would only fire if the targeted
    // account is removed mid-flight; `classify_rename_error` routes
    // it to `InlineError`. Pin the same `UnlockedBusy → Unlocked`
    // rollback for the defensive branch.
    let err = PaladinError::InvalidState {
        operation: "rename",
        state: "account_not_found",
    };
    let outcome = classify_rename_error(&err);
    assert!(
        matches!(outcome, RenameErrorOutcome::InlineError(_)),
        "defensive invalid_state routes to InlineError",
    );
    let effect = RenameWorkerEffect::Failure(outcome);
    let next = rename_final_app_state(&busy, &effect)
        .expect("InlineError failure rolls back UnlockedBusy → Unlocked (dialog stays inline)");
    assert!(matches!(next, AppState::Unlocked { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn rename_final_app_state_from_non_unlocked_busy_returns_none() {
    // Defensive: a stray completion arriving while `current` is not
    // `UnlockedBusy` must not silently install a phantom `Unlocked`
    // transition over another idle state. The composer mirrors the
    // `AppState::leave_busy` contract and returns `None` for every
    // non-`UnlockedBusy` source. Pinned across every typed effect so
    // the defensive arm cannot drift with the effect routing.
    use paladin_gtk::app::state::rename_final_app_state;
    use paladin_gtk::rename_dialog::{classify_rename_error, RenameWorkerEffect};

    let path = vault_path();
    let effects = [
        RenameWorkerEffect::Success,
        RenameWorkerEffect::Failure(classify_rename_error(&PaladinError::SaveNotCommitted {
            committed: false,
            backup_path: None,
        })),
        RenameWorkerEffect::Failure(classify_rename_error(
            &PaladinError::SaveDurabilityUnconfirmed,
        )),
        RenameWorkerEffect::Failure(classify_rename_error(&PaladinError::InvalidState {
            operation: "rename",
            state: "account_not_found",
        })),
    ];
    let sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
        decide_state_from_inspect(&path, Err(invalid_header_err()))
            .expect("inspect Err yields StartupError state"),
    ];
    for effect in &effects {
        for source in &sources {
            assert!(
                rename_final_app_state(source, effect).is_none(),
                "rename_final_app_state must return None for non-UnlockedBusy source={source:?} effect={effect:?}",
            );
        }
    }
}

#[test]
fn rename_final_app_state_mirrors_leave_busy_for_every_variant() {
    // Cross-check: the composer is a name-the-call-site wrapper over
    // `AppState::leave_busy`, not a re-derivation. The `Some` /
    // `None` partition across source states must mirror `leave_busy`
    // byte-for-byte (and the result on `Some` must match
    // `leave_busy`'s `Unlocked { path }` projection) so the wrapper
    // can't drift away from the underlying method without breaking
    // here first. Pinned across every typed effect because the
    // composer ignores `effect` for the state decision.
    use paladin_gtk::app::state::rename_final_app_state;
    use paladin_gtk::rename_dialog::{classify_rename_error, RenameWorkerEffect};

    let path = vault_path();
    let effects = [
        RenameWorkerEffect::Success,
        RenameWorkerEffect::Failure(classify_rename_error(&PaladinError::SaveNotCommitted {
            committed: true,
            backup_path: None,
        })),
        RenameWorkerEffect::Failure(classify_rename_error(
            &PaladinError::SaveDurabilityUnconfirmed,
        )),
        RenameWorkerEffect::Failure(classify_rename_error(&PaladinError::InvalidState {
            operation: "rename",
            state: "account_not_found",
        })),
    ];
    let sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
        AppState::UnlockedBusy { path: path.clone() },
        decide_state_from_inspect(&path, Err(invalid_header_err()))
            .expect("inspect Err yields StartupError state"),
    ];
    for effect in &effects {
        for source in &sources {
            let composed = rename_final_app_state(source, effect);
            let direct = source.clone().leave_busy();
            match (&composed, &direct) {
                (Some(a), Some(b)) => {
                    assert_eq!(
                        std::mem::discriminant::<AppState>(a),
                        std::mem::discriminant::<AppState>(b),
                        "wrapper variant must mirror leave_busy for source={source:?} effect={effect:?}",
                    );
                    assert_eq!(
                        a.path().map(Path::to_path_buf),
                        b.path().map(Path::to_path_buf),
                        "wrapper path must mirror leave_busy for source={source:?} effect={effect:?}",
                    );
                }
                (None, None) => {}
                _ => panic!(
                    "wrapper / leave_busy Some/None partition diverged for source={source:?} effect={effect:?}: composed={composed:?} direct={direct:?}",
                ),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// should_drop_rename_dialog_after — drop-decision projection
// ---------------------------------------------------------------------------
//
// Symmetric partner of `should_drop_unlock_dialog_after` for the
// rename path. `AppMsg::RenameWorkerCompleted` consults this to
// decide whether to detach the live `RenameDialogComponent` from
// the content tree after applying the worker outcome:
//
// * `Success` → drop (the dialog dismisses itself and the visible
//   row label updates to the new value).
// * `Failure(RestorePrior)` → stay mounted (the dialog rolls the
//   visible label back to the pre-submit value and renders the
//   typed inline error).
// * `Failure(KeepNewWithWarning)` → stay mounted (the visible
//   label keeps the new value and the warning attaches to the
//   dialog body).
// * `Failure(InlineError)` → stay mounted (the defensive branch
//   renders the typed inline error without transitioning out).
//
// The projection inspects only the typed `RenameWorkerEffect`
// variant — it does not consult `AppState`, the live `(Vault,
// Store)` pair, or the `RenameDialogState` — so the side-effect
// decision in `AppModel::update` stays unit-testable without
// spinning up GTK / libadwaita.

#[test]
fn should_drop_rename_dialog_after_success_returns_true() {
    use paladin_gtk::app::state::should_drop_rename_dialog_after;
    use paladin_gtk::rename_dialog::RenameWorkerEffect;

    let effect = RenameWorkerEffect::Success;
    assert!(
        should_drop_rename_dialog_after(&effect),
        "Success must drop the rename dialog so the row label updates and the dialog dismisses",
    );
}

#[test]
fn should_drop_rename_dialog_after_failure_restore_prior_returns_false() {
    use paladin_gtk::app::state::should_drop_rename_dialog_after;
    use paladin_gtk::rename_dialog::{
        classify_rename_error, RenameErrorOutcome, RenameWorkerEffect,
    };

    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let outcome = classify_rename_error(&err);
    assert!(
        matches!(outcome, RenameErrorOutcome::RestorePrior(_)),
        "save_not_committed routes to RestorePrior",
    );
    let effect = RenameWorkerEffect::Failure(outcome);
    assert!(
        !should_drop_rename_dialog_after(&effect),
        "RestorePrior keeps the dialog mounted so the inline error is visible",
    );
}

#[test]
fn should_drop_rename_dialog_after_failure_keep_new_with_warning_returns_false() {
    use paladin_gtk::app::state::should_drop_rename_dialog_after;
    use paladin_gtk::rename_dialog::{
        classify_rename_error, RenameErrorOutcome, RenameWorkerEffect,
    };

    let err = PaladinError::SaveDurabilityUnconfirmed;
    let outcome = classify_rename_error(&err);
    assert!(
        matches!(outcome, RenameErrorOutcome::KeepNewWithWarning(_)),
        "save_durability_unconfirmed routes to KeepNewWithWarning",
    );
    let effect = RenameWorkerEffect::Failure(outcome);
    assert!(
        !should_drop_rename_dialog_after(&effect),
        "KeepNewWithWarning keeps the dialog mounted so the warning attaches to the body",
    );
}

#[test]
fn should_drop_rename_dialog_after_failure_inline_error_returns_false() {
    use paladin_gtk::app::state::should_drop_rename_dialog_after;
    use paladin_gtk::rename_dialog::{
        classify_rename_error, RenameErrorOutcome, RenameWorkerEffect,
    };

    let err = PaladinError::InvalidState {
        operation: "rename",
        state: "account_not_found",
    };
    let outcome = classify_rename_error(&err);
    assert!(
        matches!(outcome, RenameErrorOutcome::InlineError(_)),
        "invalid_state routes to defensive InlineError",
    );
    let effect = RenameWorkerEffect::Failure(outcome);
    assert!(
        !should_drop_rename_dialog_after(&effect),
        "defensive InlineError keeps the dialog mounted so the typed error is visible",
    );
}

#[test]
fn should_drop_rename_dialog_after_partitions_on_success_only() {
    // Cross-check: the projection partitions effects into "drop"
    // (Success only) and "keep" (every Failure variant). Pin the
    // partition across every typed outcome so a future routing
    // refinement that swaps a Failure branch into the drop side
    // (or vice versa) is caught here.
    use paladin_gtk::app::state::should_drop_rename_dialog_after;
    use paladin_gtk::rename_dialog::{classify_rename_error, RenameWorkerEffect};

    let drop_effects = [RenameWorkerEffect::Success];
    let keep_effects = [
        RenameWorkerEffect::Failure(classify_rename_error(&PaladinError::SaveNotCommitted {
            committed: false,
            backup_path: None,
        })),
        RenameWorkerEffect::Failure(classify_rename_error(&PaladinError::SaveNotCommitted {
            committed: true,
            backup_path: None,
        })),
        RenameWorkerEffect::Failure(classify_rename_error(
            &PaladinError::SaveDurabilityUnconfirmed,
        )),
        RenameWorkerEffect::Failure(classify_rename_error(&PaladinError::InvalidState {
            operation: "rename",
            state: "account_not_found",
        })),
    ];
    for effect in &drop_effects {
        assert!(
            should_drop_rename_dialog_after(effect),
            "drop partition expects true for effect={effect:?}",
        );
    }
    for effect in &keep_effects {
        assert!(
            !should_drop_rename_dialog_after(effect),
            "keep partition expects false for effect={effect:?}",
        );
    }
}

// ---------------------------------------------------------------------------
// should_refresh_list_after_rename — list-refresh decision projection
// ---------------------------------------------------------------------------
//
// `AppMsg::RenameWorkerCompleted` consults this to decide whether to
// re-project rows off the freshly reinstalled `(Vault, Store)` pair
// and emit `AccountListMsg::Refresh` so the visible row label
// matches the post-mutation vault state per
// `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
// `AccountListComponent` ("Refresh the store after every vault
// mutation … without reordering surviving rows"):
//
// * `Success` → `true`. The rename committed and the new label
//   must surface in the list.
// * `Failure(RestorePrior)` → `false`. `Vault::mutate_and_save`
//   rolled back to the pre-attempt snapshot; the visible rows
//   already match the post-rollback state.
// * `Failure(KeepNewWithWarning)` → `true`. Primary save succeeded
//   so the new label is durable in memory; the list must surface
//   it even though the parent fsync was uncertain.
// * `Failure(InlineError)` → `false`. Defensive branch where
//   `Vault::rename` rejected the call before any mutation
//   occurred.
//
// The projection inspects only the typed `RenameWorkerEffect`
// variant so the side-effect decision in `AppModel::update` stays
// unit-testable without spinning up GTK / libadwaita.

#[test]
fn should_refresh_list_after_rename_success_returns_true() {
    use paladin_gtk::app::state::should_refresh_list_after_rename;
    use paladin_gtk::rename_dialog::RenameWorkerEffect;

    let effect = RenameWorkerEffect::Success;
    assert!(
        should_refresh_list_after_rename(&effect),
        "Success refreshes the list so the row label updates to the new value",
    );
}

#[test]
fn should_refresh_list_after_rename_failure_restore_prior_returns_false() {
    use paladin_gtk::app::state::should_refresh_list_after_rename;
    use paladin_gtk::rename_dialog::{
        classify_rename_error, RenameErrorOutcome, RenameWorkerEffect,
    };

    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let outcome = classify_rename_error(&err);
    assert!(
        matches!(outcome, RenameErrorOutcome::RestorePrior(_)),
        "save_not_committed routes to RestorePrior",
    );
    let effect = RenameWorkerEffect::Failure(outcome);
    assert!(
        !should_refresh_list_after_rename(&effect),
        "RestorePrior leaves vault state unchanged so no list refresh is needed",
    );
}

#[test]
fn should_refresh_list_after_rename_failure_keep_new_with_warning_returns_true() {
    use paladin_gtk::app::state::should_refresh_list_after_rename;
    use paladin_gtk::rename_dialog::{
        classify_rename_error, RenameErrorOutcome, RenameWorkerEffect,
    };

    let err = PaladinError::SaveDurabilityUnconfirmed;
    let outcome = classify_rename_error(&err);
    assert!(
        matches!(outcome, RenameErrorOutcome::KeepNewWithWarning(_)),
        "save_durability_unconfirmed routes to KeepNewWithWarning",
    );
    let effect = RenameWorkerEffect::Failure(outcome);
    assert!(
        should_refresh_list_after_rename(&effect),
        "KeepNewWithWarning commits the new label in memory; the list must surface it",
    );
}

#[test]
fn should_refresh_list_after_rename_failure_inline_error_returns_false() {
    use paladin_gtk::app::state::should_refresh_list_after_rename;
    use paladin_gtk::rename_dialog::{
        classify_rename_error, RenameErrorOutcome, RenameWorkerEffect,
    };

    let err = PaladinError::InvalidState {
        operation: "rename",
        state: "account_not_found",
    };
    let outcome = classify_rename_error(&err);
    assert!(
        matches!(outcome, RenameErrorOutcome::InlineError(_)),
        "invalid_state routes to defensive InlineError",
    );
    let effect = RenameWorkerEffect::Failure(outcome);
    assert!(
        !should_refresh_list_after_rename(&effect),
        "defensive InlineError leaves vault state unchanged so no list refresh is needed",
    );
}

#[test]
fn should_refresh_list_after_rename_partitions_on_committed_outcomes() {
    // Cross-check: the projection partitions effects into "refresh"
    // (`Success` + `KeepNewWithWarning`) and "skip" (`RestorePrior`
    // + defensive `InlineError`). Pin the partition across every
    // typed outcome so a future routing refinement that flips a
    // branch is caught here.
    use paladin_gtk::app::state::should_refresh_list_after_rename;
    use paladin_gtk::rename_dialog::{classify_rename_error, RenameWorkerEffect};

    let refresh_effects = [
        RenameWorkerEffect::Success,
        RenameWorkerEffect::Failure(classify_rename_error(
            &PaladinError::SaveDurabilityUnconfirmed,
        )),
    ];
    let skip_effects = [
        RenameWorkerEffect::Failure(classify_rename_error(&PaladinError::SaveNotCommitted {
            committed: false,
            backup_path: None,
        })),
        RenameWorkerEffect::Failure(classify_rename_error(&PaladinError::SaveNotCommitted {
            committed: true,
            backup_path: None,
        })),
        RenameWorkerEffect::Failure(classify_rename_error(&PaladinError::InvalidState {
            operation: "rename",
            state: "account_not_found",
        })),
    ];
    for effect in &refresh_effects {
        assert!(
            should_refresh_list_after_rename(effect),
            "refresh partition expects true for effect={effect:?}",
        );
    }
    for effect in &skip_effects {
        assert!(
            !should_refresh_list_after_rename(effect),
            "skip partition expects false for effect={effect:?}",
        );
    }
}

// ---------------------------------------------------------------------------
// rename_dialog_msg_after — inline-message projection
// ---------------------------------------------------------------------------
//
// Symmetric partner of `unlock_dialog_msg_after` for the rename
// path. `AppMsg::RenameWorkerCompleted` consults this to decide
// what message (if any) to forward into the live
// `RenameDialogComponent` after applying the worker outcome:
//
// * `Success` → `None`. The dialog is being dropped — there is no
//   live controller to forward to.
// * `Failure(outcome)` → `Some(RenameDialogMsg::WorkerFailed(
//   outcome.clone()))`. The dialog stays mounted; the message
//   carries the typed `RenameErrorOutcome` so the dialog can route
//   the visible label / inline error / inline warning without
//   re-deriving the routing off the `PaladinError`.
//
// The projection returns an *owned* `Option<RenameDialogMsg>`
// rather than a borrow into the effect because `RenameWorkerEffect`
// carries the typed `RenameErrorOutcome` rather than a pre-built
// dialog message (the unlock effect carries its dialog message
// directly via `UnlockFailureEffect::SendUnlockDialogMsg`, so the
// unlock variant can borrow). The clone is cheap — the outcome
// only holds an `InlineError` / `InlineWarning` struct of an
// `ErrorKind` and a `String` body.
//
// The projection inspects only the typed `RenameWorkerEffect`
// variant — it does not consult `AppState`, the live `(Vault,
// Store)` pair, or the `RenameDialogState` — so the side-effect
// decision in `AppModel::update` stays unit-testable without
// spinning up GTK / libadwaita.

#[test]
fn rename_dialog_msg_after_success_returns_none() {
    use paladin_gtk::app::state::rename_dialog_msg_after;
    use paladin_gtk::rename_dialog::RenameWorkerEffect;

    let effect = RenameWorkerEffect::Success;
    assert!(
        rename_dialog_msg_after(&effect).is_none(),
        "Success drops the dialog, so no inline message is forwarded",
    );
}

#[test]
fn rename_dialog_msg_after_failure_restore_prior_forwards_worker_failed_with_outcome() {
    use paladin_gtk::app::state::rename_dialog_msg_after;
    use paladin_gtk::rename_dialog::{
        classify_rename_error, RenameDialogMsg, RenameErrorOutcome, RenameWorkerEffect,
    };

    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let outcome = classify_rename_error(&err);
    assert!(
        matches!(outcome, RenameErrorOutcome::RestorePrior(_)),
        "save_not_committed routes to RestorePrior",
    );
    let effect = RenameWorkerEffect::Failure(outcome);
    let msg = rename_dialog_msg_after(&effect)
        .expect("Failure forwards a WorkerFailed message so the dialog stays mounted");
    match msg {
        RenameDialogMsg::WorkerFailed(RenameErrorOutcome::RestorePrior(inline)) => {
            assert_eq!(
                inline.kind,
                ErrorKind::SaveNotCommitted,
                "RestorePrior must round-trip the SaveNotCommitted ErrorKind",
            );
        }
        other => panic!("expected RenameDialogMsg::WorkerFailed(RestorePrior), got {other:?}"),
    }
}

#[test]
fn rename_dialog_msg_after_failure_keep_new_with_warning_forwards_worker_failed_with_outcome() {
    use paladin_gtk::app::state::rename_dialog_msg_after;
    use paladin_gtk::rename_dialog::{
        classify_rename_error, RenameDialogMsg, RenameErrorOutcome, RenameWorkerEffect,
    };

    let err = PaladinError::SaveDurabilityUnconfirmed;
    let outcome = classify_rename_error(&err);
    assert!(
        matches!(outcome, RenameErrorOutcome::KeepNewWithWarning(_)),
        "save_durability_unconfirmed routes to KeepNewWithWarning",
    );
    let effect = RenameWorkerEffect::Failure(outcome);
    let msg = rename_dialog_msg_after(&effect)
        .expect("Failure forwards a WorkerFailed message so the dialog stays mounted");
    match msg {
        RenameDialogMsg::WorkerFailed(RenameErrorOutcome::KeepNewWithWarning(warning)) => {
            assert_eq!(
                warning.kind,
                ErrorKind::SaveDurabilityUnconfirmed,
                "KeepNewWithWarning must round-trip the SaveDurabilityUnconfirmed ErrorKind",
            );
        }
        other => {
            panic!("expected RenameDialogMsg::WorkerFailed(KeepNewWithWarning), got {other:?}")
        }
    }
}

#[test]
fn rename_dialog_msg_after_failure_inline_error_forwards_worker_failed_with_outcome() {
    use paladin_gtk::app::state::rename_dialog_msg_after;
    use paladin_gtk::rename_dialog::{
        classify_rename_error, RenameDialogMsg, RenameErrorOutcome, RenameWorkerEffect,
    };

    let err = PaladinError::InvalidState {
        operation: "rename",
        state: "account_not_found",
    };
    let outcome = classify_rename_error(&err);
    assert!(
        matches!(outcome, RenameErrorOutcome::InlineError(_)),
        "invalid_state routes to defensive InlineError",
    );
    let effect = RenameWorkerEffect::Failure(outcome);
    let msg = rename_dialog_msg_after(&effect)
        .expect("Failure forwards a WorkerFailed message so the dialog stays mounted");
    match msg {
        RenameDialogMsg::WorkerFailed(RenameErrorOutcome::InlineError(inline)) => {
            assert_eq!(
                inline.kind,
                ErrorKind::InvalidState,
                "InlineError must round-trip the defensive InvalidState ErrorKind",
            );
        }
        other => panic!("expected RenameDialogMsg::WorkerFailed(InlineError), got {other:?}"),
    }
}

#[test]
fn rename_dialog_msg_after_is_mutually_exclusive_with_should_drop() {
    // Cross-check: the inline-message projection must report `Some`
    // exactly when `should_drop_rename_dialog_after` reports
    // `false` (dialog stays mounted), and `None` when the dispatch
    // drops the dialog. Pinned across every typed effect so the two
    // projections can't drift apart silently — a future routing
    // refinement that puts a Failure variant on the drop side would
    // need to update both helpers in lockstep, and this test
    // catches the partial update.
    use paladin_gtk::app::state::{rename_dialog_msg_after, should_drop_rename_dialog_after};
    use paladin_gtk::rename_dialog::{classify_rename_error, RenameWorkerEffect};

    let effects = [
        RenameWorkerEffect::Success,
        RenameWorkerEffect::Failure(classify_rename_error(&PaladinError::SaveNotCommitted {
            committed: false,
            backup_path: None,
        })),
        RenameWorkerEffect::Failure(classify_rename_error(&PaladinError::SaveNotCommitted {
            committed: true,
            backup_path: None,
        })),
        RenameWorkerEffect::Failure(classify_rename_error(
            &PaladinError::SaveDurabilityUnconfirmed,
        )),
        RenameWorkerEffect::Failure(classify_rename_error(&PaladinError::InvalidState {
            operation: "rename",
            state: "account_not_found",
        })),
    ];
    for effect in &effects {
        let drops = should_drop_rename_dialog_after(effect);
        let has_msg = rename_dialog_msg_after(effect).is_some();
        assert_eq!(
            drops, !has_msg,
            "drops/has_msg must be mutually exclusive for effect={effect:?}: drops={drops}, has_msg={has_msg}",
        );
    }
}

// ---------------------------------------------------------------------------
// compose_rename_dispatch — bundling composer for the rename worker outcome
// ---------------------------------------------------------------------------
//
// Symmetric partner of `compose_unlock_dispatch` for the rename path.
// Bundles the trio (`rename_final_app_state`,
// `rename_dialog_msg_after`, `should_drop_rename_dialog_after`) into
// a single `RenameDispatch` value so `AppModel::update` can apply the
// worker outcome in one shot — no re-routing of the
// `RenameWorkerEffect` and no spreading of the trio across the
// dispatch site.
//
// Invariants pinned at the trio level carry through:
//
// * `drop_dialog == true` iff the worker outcome is
//   `RenameWorkerEffect::Success` — the dialog drops on success and
//   stays mounted on every `Failure(RenameErrorOutcome)` variant.
// * `dialog_msg.is_some() == !drop_dialog`: a dropped dialog gets no
//   inline message; a mounted dialog gets `WorkerFailed(outcome)`.
// * `app_state` mirrors `rename_final_app_state` — `Some(Unlocked)`
//   for the `UnlockedBusy → Unlocked` rollback regardless of typed
//   effect, `None` for non-`UnlockedBusy` source states.
//
// The composer stays shape-only — it delegates to the trio without
// inspecting the typed `RenameWorkerEffect` variant itself — so the
// dispatch contract stays unit-testable without spinning up GTK /
// libadwaita.

#[test]
fn compose_rename_dispatch_success_bundles_drop_and_unlocked_rollback() {
    use paladin_gtk::app::state::compose_rename_dispatch;
    use paladin_gtk::rename_dialog::RenameWorkerEffect;

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let effect = RenameWorkerEffect::Success;
    let dispatch = compose_rename_dispatch(&busy, &effect);
    assert!(
        dispatch.drop_dialog,
        "Success drops the RenameDialog controller so the row label updates and the dialog dismisses",
    );
    assert!(
        dispatch.dialog_msg.is_none(),
        "Success drops the dialog, so no inline message is forwarded",
    );
    let next = dispatch
        .app_state
        .expect("Success rolls UnlockedBusy back to Unlocked");
    assert!(
        matches!(next, AppState::Unlocked { .. }),
        "Success rollback target must be Unlocked, got {next:?}",
    );
    assert_path_eq(&next, &path);
}

#[test]
fn compose_rename_dispatch_failure_restore_prior_keeps_dialog_with_msg_and_unlocked_rollback() {
    use paladin_gtk::app::state::compose_rename_dispatch;
    use paladin_gtk::rename_dialog::{
        classify_rename_error, RenameDialogMsg, RenameErrorOutcome, RenameWorkerEffect,
    };

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let outcome = classify_rename_error(&err);
    assert!(matches!(outcome, RenameErrorOutcome::RestorePrior(_)));
    let effect = RenameWorkerEffect::Failure(outcome);
    let dispatch = compose_rename_dispatch(&busy, &effect);
    assert!(
        !dispatch.drop_dialog,
        "RestorePrior keeps the RenameDialog mounted so the inline error is visible",
    );
    let msg = dispatch
        .dialog_msg
        .as_ref()
        .expect("RestorePrior forwards a WorkerFailed message");
    assert!(
        matches!(
            msg,
            RenameDialogMsg::WorkerFailed(RenameErrorOutcome::RestorePrior(_))
        ),
        "RestorePrior must forward WorkerFailed(RestorePrior), got {msg:?}",
    );
    let next = dispatch
        .app_state
        .expect("Failure still rolls UnlockedBusy back to Unlocked");
    assert!(matches!(next, AppState::Unlocked { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn compose_rename_dispatch_failure_keep_new_with_warning_keeps_dialog_with_msg_and_unlocked_rollback(
) {
    use paladin_gtk::app::state::compose_rename_dispatch;
    use paladin_gtk::rename_dialog::{
        classify_rename_error, RenameDialogMsg, RenameErrorOutcome, RenameWorkerEffect,
    };

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = PaladinError::SaveDurabilityUnconfirmed;
    let outcome = classify_rename_error(&err);
    assert!(matches!(outcome, RenameErrorOutcome::KeepNewWithWarning(_)));
    let effect = RenameWorkerEffect::Failure(outcome);
    let dispatch = compose_rename_dispatch(&busy, &effect);
    assert!(
        !dispatch.drop_dialog,
        "KeepNewWithWarning keeps the RenameDialog mounted so the warning attaches to the body",
    );
    let msg = dispatch
        .dialog_msg
        .as_ref()
        .expect("KeepNewWithWarning forwards a WorkerFailed message");
    assert!(matches!(
        msg,
        RenameDialogMsg::WorkerFailed(RenameErrorOutcome::KeepNewWithWarning(_)),
    ));
    let next = dispatch
        .app_state
        .expect("Failure still rolls UnlockedBusy back to Unlocked");
    assert!(matches!(next, AppState::Unlocked { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn compose_rename_dispatch_failure_inline_error_keeps_dialog_with_msg_and_unlocked_rollback() {
    use paladin_gtk::app::state::compose_rename_dispatch;
    use paladin_gtk::rename_dialog::{
        classify_rename_error, RenameDialogMsg, RenameErrorOutcome, RenameWorkerEffect,
    };

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = PaladinError::InvalidState {
        operation: "rename",
        state: "account_not_found",
    };
    let outcome = classify_rename_error(&err);
    assert!(matches!(outcome, RenameErrorOutcome::InlineError(_)));
    let effect = RenameWorkerEffect::Failure(outcome);
    let dispatch = compose_rename_dispatch(&busy, &effect);
    assert!(
        !dispatch.drop_dialog,
        "defensive InlineError keeps the RenameDialog mounted so the typed error is visible",
    );
    let msg = dispatch
        .dialog_msg
        .as_ref()
        .expect("defensive InlineError forwards a WorkerFailed message");
    assert!(matches!(
        msg,
        RenameDialogMsg::WorkerFailed(RenameErrorOutcome::InlineError(_)),
    ));
    let next = dispatch
        .app_state
        .expect("Failure still rolls UnlockedBusy back to Unlocked");
    assert!(matches!(next, AppState::Unlocked { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn compose_rename_dispatch_mirrors_trio_for_every_effect() {
    use paladin_gtk::app::state::{
        compose_rename_dispatch, rename_dialog_msg_after, rename_final_app_state,
        rename_success_toast_after, should_drop_rename_dialog_after,
        should_refresh_list_after_rename,
    };
    use paladin_gtk::rename_dialog::{classify_rename_error, RenameWorkerEffect};

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let effects = [
        RenameWorkerEffect::Success,
        RenameWorkerEffect::Failure(classify_rename_error(&PaladinError::SaveNotCommitted {
            committed: false,
            backup_path: None,
        })),
        RenameWorkerEffect::Failure(classify_rename_error(&PaladinError::SaveNotCommitted {
            committed: true,
            backup_path: None,
        })),
        RenameWorkerEffect::Failure(classify_rename_error(
            &PaladinError::SaveDurabilityUnconfirmed,
        )),
        RenameWorkerEffect::Failure(classify_rename_error(&PaladinError::InvalidState {
            operation: "rename",
            state: "account_not_found",
        })),
    ];
    for effect in &effects {
        let dispatch = compose_rename_dispatch(&busy, effect);
        assert_eq!(
            dispatch.drop_dialog,
            should_drop_rename_dialog_after(effect),
            "drop_dialog must mirror the trio for effect={effect:?}",
        );
        assert_eq!(
            dispatch.refresh_list,
            should_refresh_list_after_rename(effect),
            "refresh_list must mirror the helper for effect={effect:?}",
        );
        assert_eq!(
            dispatch.success_toast,
            rename_success_toast_after(effect),
            "success_toast must mirror the projection for effect={effect:?}",
        );
        let trio_msg = rename_dialog_msg_after(effect);
        match (&dispatch.dialog_msg, &trio_msg) {
            (None, None) | (Some(_), Some(_)) => {}
            other => panic!(
                "dialog_msg Some/None must mirror the trio for effect={effect:?}, got {other:?}",
            ),
        }
        let trio_state = rename_final_app_state(&busy, effect);
        match (&dispatch.app_state, &trio_state) {
            (None, None) => {}
            (Some(a), Some(b)) => {
                assert_eq!(
                    std::mem::discriminant::<AppState>(a),
                    std::mem::discriminant::<AppState>(b),
                    "app_state variant must mirror the trio for effect={effect:?}",
                );
                assert_eq!(
                    a.path().map(Path::to_path_buf),
                    b.path().map(Path::to_path_buf),
                    "app_state path must mirror the trio for effect={effect:?}",
                );
            }
            other => panic!(
                "app_state Some/None must mirror the trio for effect={effect:?}, got {other:?}",
            ),
        }
    }
}

#[test]
fn compose_rename_dispatch_from_non_unlocked_busy_returns_no_app_state() {
    // Defensive: when the rename worker returns but `current` is not
    // `UnlockedBusy` (a stray dispatch from any other source state),
    // the composer mirrors `rename_final_app_state` and reports
    // `app_state = None`. `drop_dialog` and `dialog_msg` still mirror
    // the trio because they inspect only the typed effect — the
    // worker outcome is visible to the dialog regardless of the
    // source state.
    use paladin_gtk::app::state::compose_rename_dispatch;
    use paladin_gtk::rename_dialog::{
        classify_rename_error, RenameDialogMsg, RenameErrorOutcome, RenameWorkerEffect,
    };

    let path = vault_path();
    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let outcome = classify_rename_error(&err);
    assert!(matches!(outcome, RenameErrorOutcome::RestorePrior(_)));
    let effect = RenameWorkerEffect::Failure(outcome);
    let invalid_sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
    ];
    for source in &invalid_sources {
        let dispatch = compose_rename_dispatch(source, &effect);
        assert!(
            !dispatch.drop_dialog,
            "Failure keeps the dialog mounted regardless of source={source:?}",
        );
        assert!(
            matches!(
                dispatch.dialog_msg.as_ref(),
                Some(RenameDialogMsg::WorkerFailed(
                    RenameErrorOutcome::RestorePrior(_)
                )),
            ),
            "Failure forwards WorkerFailed regardless of source={source:?}",
        );
        assert!(
            dispatch.app_state.is_none(),
            "non-UnlockedBusy source={source:?} must refuse to install a phantom Unlocked, \
             got {:?}",
            dispatch.app_state,
        );
    }
}

// rename_success_toast_after — toast-body projection for the rename
// worker outcome. `AppMsg::RenameWorkerCompleted` consults this to
// decide whether to raise an `AdwToast` on the `adw::ToastOverlay`
// per `IMPLEMENTATION_PLAN_04_GTK.md` §"Milestone 7 checklist" >
// "In-app account rename" ("On success, refresh
// `AccountListComponent` from the returned vault, close the dialog,
// and surface a status / toast confirmation."). The projection
// inspects only the typed `RenameWorkerEffect` variant so the
// side-effect decision in `AppModel::update` stays unit-testable
// without spinning up GTK / libadwaita.

#[test]
fn rename_success_toast_after_success_returns_body() {
    use paladin_gtk::app::state::rename_success_toast_after;
    use paladin_gtk::rename_dialog::{format_rename_dialog_success_toast, RenameWorkerEffect};

    let toast = rename_success_toast_after(&RenameWorkerEffect::Success)
        .expect("Success must surface a confirmation toast");
    assert_eq!(
        toast,
        format_rename_dialog_success_toast(),
        "toast body must come from format_rename_dialog_success_toast so wording stays single-sourced",
    );
}

#[test]
fn rename_success_toast_after_failure_returns_none() {
    use paladin_gtk::app::state::rename_success_toast_after;
    use paladin_gtk::rename_dialog::{classify_rename_error, RenameWorkerEffect};

    let failures = [
        PaladinError::SaveNotCommitted {
            committed: false,
            backup_path: None,
        },
        PaladinError::SaveNotCommitted {
            committed: true,
            backup_path: None,
        },
        PaladinError::SaveDurabilityUnconfirmed,
        PaladinError::InvalidState {
            operation: "rename",
            state: "account_not_found",
        },
    ];
    for err in &failures {
        let outcome = classify_rename_error(err);
        let effect = RenameWorkerEffect::Failure(outcome);
        assert!(
            rename_success_toast_after(&effect).is_none(),
            "Failure must not raise a success toast for err={err:?}",
        );
    }
}

#[test]
fn compose_rename_dispatch_populates_success_toast_only_on_success() {
    // `compose_rename_dispatch` bundles `rename_success_toast_after`
    // alongside the existing drop-dialog / refresh-list / dialog-msg /
    // app-state decisions so the dispatch site can raise the toast in
    // one shot. The success branch carries the toast body so the
    // widget layer just adds it as an `adw::Toast::new(&body)`; the
    // failure branches stay `None` so the dialog's inline error /
    // warning is the only surface that conveys the typed outcome.
    use paladin_gtk::app::state::{compose_rename_dispatch, rename_success_toast_after};
    use paladin_gtk::rename_dialog::{classify_rename_error, RenameWorkerEffect};

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let effects = [
        RenameWorkerEffect::Success,
        RenameWorkerEffect::Failure(classify_rename_error(&PaladinError::SaveNotCommitted {
            committed: false,
            backup_path: None,
        })),
        RenameWorkerEffect::Failure(classify_rename_error(
            &PaladinError::SaveDurabilityUnconfirmed,
        )),
        RenameWorkerEffect::Failure(classify_rename_error(&PaladinError::InvalidState {
            operation: "rename",
            state: "account_not_found",
        })),
    ];
    for effect in &effects {
        let dispatch = compose_rename_dispatch(&busy, effect);
        assert_eq!(
            dispatch.success_toast,
            rename_success_toast_after(effect),
            "success_toast must mirror the projection for effect={effect:?}",
        );
    }
}

// ---------------------------------------------------------------------------
// apply_rename_dispatch_inplace — `AppModel::update` mut-state wrapper
// ---------------------------------------------------------------------------
//
// Symmetric partner of `apply_unlock_dispatch_inplace` for the rename
// path. `compose_rename_dispatch(&AppState, &RenameWorkerEffect) ->
// RenameDispatch` bundles the three worker-completion decisions; the
// wrapper here lets `AppMsg::RenameWorkerCompleted` install the new
// `dispatch.app_state` against the cached `AppState` in place,
// mirroring `apply_submit_rename_inplace`'s contract for the entry
// transition. The remaining `dialog_msg` / `drop_dialog` projections
// drive widget-side work in the handler and are not the wrapper's
// concern.

#[test]
fn apply_rename_dispatch_inplace_success_rolls_back_to_unlocked_and_returns_true() {
    // Worker reported `Ok(())`: `compose_rename_dispatch` carries
    // `Some(Unlocked(path))` in `app_state`. The wrapper installs the
    // rollback against the cached `UnlockedBusy` state and returns
    // `true` so `AppModel::update` can release the busy gate and drop
    // the `RenameDialogComponent`.
    use paladin_gtk::app::state::{apply_rename_dispatch_inplace, compose_rename_dispatch};
    use paladin_gtk::rename_dialog::RenameWorkerEffect;

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let effect = RenameWorkerEffect::Success;
    let dispatch = compose_rename_dispatch(&busy, &effect);
    let mut state = busy.clone();
    let transitioned = apply_rename_dispatch_inplace(&mut state, &dispatch);
    assert!(
        transitioned,
        "apply_rename_dispatch_inplace must return true on the Success rollback",
    );
    assert!(
        matches!(state, AppState::Unlocked { .. }),
        "Success rollback target must be Unlocked, got {state:?}",
    );
    assert_path_eq(&state, &path);
}

#[test]
fn apply_rename_dispatch_inplace_failure_rolls_back_to_unlocked_and_returns_true() {
    // Worker reported a Failure (RestorePrior): the rename worker
    // always rolls the busy gate back to `Unlocked` regardless of
    // typed effect because `Vault::mutate_and_save` is authoritative
    // for rollback / durability-unconfirmed semantics. The wrapper
    // installs the rollback and returns `true`; widget-side work (the
    // inline message and the still-mounted dialog) is driven by the
    // remaining dispatch fields.
    use paladin_gtk::app::state::{apply_rename_dispatch_inplace, compose_rename_dispatch};
    use paladin_gtk::rename_dialog::{classify_rename_error, RenameWorkerEffect};

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let effect = RenameWorkerEffect::Failure(classify_rename_error(&err));
    let dispatch = compose_rename_dispatch(&busy, &effect);
    let mut state = busy.clone();
    let transitioned = apply_rename_dispatch_inplace(&mut state, &dispatch);
    assert!(
        transitioned,
        "apply_rename_dispatch_inplace must return true on the Failure rollback",
    );
    assert!(
        matches!(state, AppState::Unlocked { .. }),
        "Failure rollback target must be Unlocked, got {state:?}",
    );
    assert_path_eq(&state, &path);
}

#[test]
fn apply_rename_dispatch_inplace_from_non_unlocked_busy_leaves_state_unchanged_and_returns_false() {
    // Defensive: when the worker outcome arrives but the cached state
    // is not `UnlockedBusy` (a stray dispatch from any other source),
    // `compose_rename_dispatch` reports `app_state = None` to refuse a
    // phantom `Unlocked` transition. The wrapper must leave the cached
    // state untouched byte-for-byte and return `false` so
    // `AppModel::update` does not clobber an idle state with a phantom
    // rollback.
    use paladin_gtk::app::state::{apply_rename_dispatch_inplace, compose_rename_dispatch};
    use paladin_gtk::rename_dialog::{classify_rename_error, RenameWorkerEffect};

    let path = vault_path();
    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let effect = RenameWorkerEffect::Failure(classify_rename_error(&err));
    let invalid_sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
    ];
    for source in invalid_sources {
        let dispatch = compose_rename_dispatch(&source, &effect);
        assert!(
            dispatch.app_state.is_none(),
            "fixture invariant: non-UnlockedBusy source must carry app_state=None",
        );
        let original_discriminant = std::mem::discriminant::<AppState>(&source);
        let original_path = source.path().map(Path::to_path_buf);
        let mut state = source.clone();
        let transitioned = apply_rename_dispatch_inplace(&mut state, &dispatch);
        assert!(
            !transitioned,
            "apply_rename_dispatch_inplace must return false when dispatch.app_state is None \
             for source={source:?}",
        );
        assert_eq!(
            std::mem::discriminant::<AppState>(&state),
            original_discriminant,
            "wrapper must leave variant unchanged when dispatch.app_state is None \
             for source={source:?}",
        );
        assert_eq!(
            state.path().map(Path::to_path_buf),
            original_path,
            "wrapper must leave path unchanged when dispatch.app_state is None \
             for source={source:?}",
        );
    }
}

#[test]
fn apply_rename_dispatch_inplace_mirrors_compose_rename_dispatch_for_every_effect() {
    // Cross-check: the wrapper must mirror the
    // `compose_rename_dispatch.app_state` Some/None partition exactly.
    // The cached source is always `UnlockedBusy(path)` since that is
    // the only state `AppModel::update` ever reaches when the worker
    // returns.
    use paladin_gtk::app::state::{apply_rename_dispatch_inplace, compose_rename_dispatch};
    use paladin_gtk::rename_dialog::{classify_rename_error, RenameWorkerEffect};

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let effects = [
        RenameWorkerEffect::Success,
        RenameWorkerEffect::Failure(classify_rename_error(&PaladinError::SaveNotCommitted {
            committed: false,
            backup_path: None,
        })),
        RenameWorkerEffect::Failure(classify_rename_error(&PaladinError::SaveNotCommitted {
            committed: true,
            backup_path: None,
        })),
        RenameWorkerEffect::Failure(classify_rename_error(
            &PaladinError::SaveDurabilityUnconfirmed,
        )),
        RenameWorkerEffect::Failure(classify_rename_error(&PaladinError::InvalidState {
            operation: "rename",
            state: "account_not_found",
        })),
    ];
    for effect in &effects {
        let dispatch = compose_rename_dispatch(&busy, effect);
        let mut state = busy.clone();
        let transitioned = apply_rename_dispatch_inplace(&mut state, &dispatch);
        if let Some(expected) = dispatch.app_state.as_ref() {
            assert!(
                transitioned,
                "wrapper must return true when dispatch.app_state is Some for effect={effect:?}",
            );
            assert_eq!(
                std::mem::discriminant::<AppState>(&state),
                std::mem::discriminant::<AppState>(expected),
                "wrapper variant must mirror composer for effect={effect:?}",
            );
            assert_eq!(
                state.path().map(Path::to_path_buf),
                expected.path().map(Path::to_path_buf),
                "wrapper path must mirror composer for effect={effect:?}",
            );
        } else {
            assert!(
                !transitioned,
                "wrapper must return false when dispatch.app_state is None for effect={effect:?}",
            );
            assert_eq!(
                std::mem::discriminant::<AppState>(&state),
                std::mem::discriminant::<AppState>(&busy),
                "wrapper must leave variant unchanged when dispatch.app_state is None \
                 for effect={effect:?}",
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Full rename pipeline composition order
// ---------------------------------------------------------------------------
//
// `AppModel::update`'s `AppMsg::RenameDialogAction(SubmitLabel)` and
// `AppMsg::RenameWorkerCompleted` handlers chain the rename helpers
// in a fixed order:
//
//   1. `compose_rename_worker_input(state, pair, account_id, label, now)`
//      over the `Unlocked` state takes the live `(Vault, Store)` pair
//      out of `AppModel.vault` and bundles a `RenameWorkerInput`.
//   2. `apply_submit_rename_inplace(state)` transitions `Unlocked →
//      UnlockedBusy` so `is_busy()` / `allows_mutating_menu()` cover
//      the worker's lifetime.
//   3. `run_rename_worker(input)` calls
//      `Vault::mutate_and_save(|v| v.rename(...))` and bundles the
//      outcome into a `RenameWorkerCompletion`.
//   4. `apply_rename_vault_install_inplace(&mut vault_slot, (vault,
//      store))` reinstalls the worker-returned pair into
//      `AppModel.vault` regardless of typed effect.
//   5. `compose_rename_dispatch(state, &effect)` +
//      `apply_rename_dispatch_inplace(state, &dispatch)` transition
//      `UnlockedBusy → Unlocked` and project the dialog message /
//      drop-decision the widget layer applies.
//
// Each helper has its own unit test. The tests below pin the
// *composition order* so a future reorder cannot silently break the
// dispatch sequence the widget layer relies on.

#[test]
fn rename_pipeline_success_returns_to_unlocked_with_renamed_vault_and_drops_dialog() {
    use paladin_core::{validate_manual, AccountInput, AccountKindInput, Algorithm, IconHintInput};
    use paladin_gtk::app::state::{
        apply_rename_dispatch_inplace, apply_rename_vault_install_inplace, compose_rename_dispatch,
    };
    use paladin_gtk::rename_dialog::{
        run_rename_worker, RenameWorkerCompletion, RenameWorkerEffect,
    };
    use secrecy::SecretString;

    let (_tempdir, path, pair) = fresh_plaintext_vault_pair();
    let (mut vault, store) = pair;
    let input = AccountInput {
        label: "old-label".to_string(),
        issuer: Some("issuer".to_string()),
        secret: SecretString::from("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Totp,
        period_secs: None,
        counter: None,
        icon_hint: IconHintInput::Default,
    };
    let validated =
        validate_manual(input, SystemTime::UNIX_EPOCH).expect("totp account input validates");
    let account_id = vault.add(validated.account);
    vault.save(&store).expect("commit seeded account");

    // 1. Compose worker input from `Unlocked` over the live pair.
    let mut state = AppState::Unlocked { path: path.clone() };
    let mut vault_slot: Option<(Vault, Store)> = Some((vault, store));
    let worker_input = compose_rename_worker_input(
        &state,
        vault_slot.take().expect("vault slot is filled"),
        account_id,
        "new-label".to_string(),
        SystemTime::UNIX_EPOCH,
    )
    .expect("compose returns Ok when state is Unlocked");

    // 2. Busy-gate transition.
    let transitioned = apply_submit_rename_inplace(&mut state);
    assert!(
        transitioned,
        "apply_submit_rename_inplace must return true on Unlocked source"
    );
    assert!(
        matches!(state, AppState::UnlockedBusy { .. }),
        "state must be UnlockedBusy"
    );

    // 3. Worker body.
    let completion = run_rename_worker(worker_input);
    let RenameWorkerCompletion {
        effect,
        vault,
        store,
    } = completion;
    assert!(
        matches!(effect, RenameWorkerEffect::Success),
        "rename worker must succeed for a valid account_id + non-empty label",
    );

    // 4. Reinstall pair.
    apply_rename_vault_install_inplace(&mut vault_slot, (vault, store));
    let (installed_vault, _) = vault_slot.as_ref().expect("pair reinstalled");
    let renamed = installed_vault
        .accounts()
        .iter()
        .find(|a| a.id() == account_id)
        .expect("renamed account survives");
    assert_eq!(renamed.label(), "new-label", "vault must reflect rename");

    // 5. Dispatch over UnlockedBusy + Success.
    let dispatch = compose_rename_dispatch(&state, &effect);
    assert!(dispatch.drop_dialog, "drop_dialog == true on Success");
    assert!(
        dispatch.dialog_msg.is_none(),
        "dialog_msg == None on Success (dropped dialog gets no message)",
    );
    let dispatched = apply_rename_dispatch_inplace(&mut state, &dispatch);
    assert!(
        dispatched,
        "apply_rename_dispatch_inplace must return true on UnlockedBusy source"
    );
    assert!(
        matches!(state, AppState::Unlocked { path: ref p } if *p == path),
        "state must be Unlocked at path after Success dispatch",
    );
}

#[test]
fn rename_pipeline_failure_restore_prior_keeps_pair_installed_and_returns_to_unlocked() {
    // Force a `save_not_committed` failure by giving the worker an
    // `account_id` that no account in the vault carries. The
    // worker's `mutate_and_save` invokes `Vault::rename` which
    // returns `PaladinError::InvalidState { state: "account_not_found"
    // }` — `classify_rename_error` routes that to
    // `RenameErrorOutcome::InlineError`. The dispatch must still
    // roll the busy-gate back to `Unlocked`, must NOT drop the
    // dialog, and must forward a `WorkerFailed(outcome)` to the
    // live dialog.
    use paladin_core::AccountId;
    use paladin_gtk::app::state::{
        apply_rename_dispatch_inplace, apply_rename_vault_install_inplace, compose_rename_dispatch,
    };
    use paladin_gtk::rename_dialog::{
        run_rename_worker, RenameDialogMsg, RenameErrorOutcome, RenameWorkerCompletion,
        RenameWorkerEffect,
    };

    let (_tempdir, path, pair) = fresh_plaintext_vault_pair();
    // Empty vault — any account_id lookup misses, triggering the
    // defensive `account_not_found` path.
    let bogus_account = AccountId::new();

    let mut state = AppState::Unlocked { path: path.clone() };
    let mut vault_slot: Option<(Vault, Store)> = Some(pair);
    let worker_input = compose_rename_worker_input(
        &state,
        vault_slot.take().expect("vault slot is filled"),
        bogus_account,
        "new-label".to_string(),
        SystemTime::UNIX_EPOCH,
    )
    .expect("compose returns Ok when state is Unlocked");

    apply_submit_rename_inplace(&mut state);

    let RenameWorkerCompletion {
        effect,
        vault,
        store,
    } = run_rename_worker(worker_input);
    match &effect {
        RenameWorkerEffect::Failure(RenameErrorOutcome::InlineError(_)) => {}
        other => panic!("expected InlineError for account_not_found, got {other:?}"),
    }

    apply_rename_vault_install_inplace(&mut vault_slot, (vault, store));
    assert!(
        vault_slot.is_some(),
        "pair must be reinstalled even on failure"
    );

    let dispatch = compose_rename_dispatch(&state, &effect);
    assert!(!dispatch.drop_dialog, "drop_dialog == false on Failure");
    match dispatch.dialog_msg.as_ref() {
        Some(RenameDialogMsg::WorkerFailed(_)) => {}
        other => panic!("dialog_msg must carry WorkerFailed on Failure, got {other:?}"),
    }
    let dispatched = apply_rename_dispatch_inplace(&mut state, &dispatch);
    assert!(
        dispatched,
        "apply_rename_dispatch_inplace must transition on UnlockedBusy source"
    );
    assert!(
        matches!(state, AppState::Unlocked { path: ref p } if *p == path),
        "state must roll back to Unlocked on Failure (busy gate always releases)",
    );
}

// ---------------------------------------------------------------------------
// run_unlock_worker — synchronous body of the spawn_blocking unlock worker
// ---------------------------------------------------------------------------
//
// `run_unlock_worker` is the body of the `gio::spawn_blocking
// paladin_core::open` worker fired by `AppModel::update` from
// `AppMsg::UnlockDialogAction(UnlockDialogOutput::SubmitLock)`. It
// consumes an `UnlockWorkerInput` by value, calls
// `paladin_core::Store::open(&path, lock)`, and bundles the outcome
// via `route_unlock_open_completion`. Extracting it lets the worker
// closure stay a thin `gio::spawn_blocking(move || run_unlock_worker(
// input))` while the real `Store::open` call stays unit-testable here
// against tempfile-backed plaintext and encrypted vaults — no GTK /
// libadwaita main loop required.

/// Create a fresh plaintext vault on disk at `<tempdir>/vault.bin`
/// and return the tempdir handle (kept alive by the caller so the
/// directory is not unlinked mid-test) plus the resolved path. The
/// in-memory `(Vault, Store)` pair is persisted via `Vault::save`
/// and then dropped before returning so the file handle is closed
/// before `Store::open` re-opens it.
fn persist_fresh_plaintext_vault() -> (tempfile::TempDir, PathBuf) {
    use std::os::unix::fs::PermissionsExt;

    let tempdir = tempfile::tempdir().expect("create tempdir for plaintext vault");
    std::fs::set_permissions(tempdir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod tempdir to 0700 so paladin_core::Store::create accepts it");
    let path = tempdir.path().join("vault.bin");
    {
        let (vault, store) = paladin_core::Store::create(&path, paladin_core::VaultInit::Plaintext)
            .expect("create plaintext vault");
        vault.save(&store).expect("persist plaintext vault to disk");
    }
    (tempdir, path)
}

/// Light Argon2 params for the encrypted-vault round-trip fixtures.
/// Keeps the KDF fast under CI (the §4.4 defaults at `m=64 MiB, t=3`
/// are designed for production and would balloon the suite); the
/// same shape is used by `tests/gtk_smoke.rs` and the paladin-tui
/// test fixtures.
fn light_argon2_params() -> paladin_core::Argon2Params {
    paladin_core::Argon2Params {
        m_kib: 8192,
        t: 1,
        p: 1,
    }
}

/// Create a fresh encrypted vault on disk at `<tempdir>/vault.bin`
/// using `passphrase` and the light Argon2 params from
/// [`light_argon2_params`]. Same drop-and-close contract as
/// [`persist_fresh_plaintext_vault`]: the file is closed before
/// returning so `Store::open` can re-open it cleanly.
fn persist_fresh_encrypted_vault(passphrase: &str) -> (tempfile::TempDir, PathBuf) {
    use secrecy::SecretString;
    use std::os::unix::fs::PermissionsExt;

    let tempdir = tempfile::tempdir().expect("create tempdir for encrypted vault");
    std::fs::set_permissions(tempdir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod tempdir to 0700 so paladin_core::Store::create accepts it");
    let path = tempdir.path().join("vault.bin");
    {
        let pp = SecretString::from(passphrase.to_string());
        let opts = paladin_core::EncryptionOptions::with_params(pp, light_argon2_params())
            .expect("encryption options accept light Argon2 params");
        let (vault, store) =
            paladin_core::Store::create(&path, paladin_core::VaultInit::Encrypted(opts))
                .expect("create encrypted vault");
        vault.save(&store).expect("persist encrypted vault to disk");
    }
    (tempdir, path)
}

#[test]
fn run_unlock_worker_opens_plaintext_vault_and_returns_live_pair() {
    // A plaintext vault on disk with the §4.3 permissions in place
    // is the simplest success path: `Store::open` returns `Ok((Vault,
    // Store))`, `route_unlock_open_completion` bundles it into a
    // success-effect `UnlockWorkerCompletion`, and the live pair is
    // available for `apply_unlock_vault_install_inplace` to write
    // through.
    let (_tempdir, path) = persist_fresh_plaintext_vault();
    let input = UnlockWorkerInput {
        path: path.clone(),
        lock: VaultLock::Plaintext,
    };

    let completion = run_unlock_worker(input);

    assert!(
        completion.pair.is_some(),
        "Plaintext open success must carry the live (Vault, Store) pair forward",
    );
    match completion.effect {
        UnlockWorkerEffect::Success(UnlockSuccessEffect::SetAppState(AppState::Unlocked {
            path: state_path,
        })) => {
            assert_eq!(
                state_path, path,
                "Success effect must carry the input vault path verbatim",
            );
        }
        other => panic!("expected Success(SetAppState(Unlocked)), got {other:?}"),
    }
}

#[test]
fn run_unlock_worker_opens_encrypted_vault_with_correct_passphrase() {
    // Encrypted-vault happy path: the worker drives the Argon2 KDF
    // off the GTK main loop and returns the decrypted `(Vault, Store)`
    // pair. The light Argon2 params keep the test fast; the same
    // shape is used by the smoke-test fixture.
    use secrecy::SecretString;

    let (_tempdir, path) = persist_fresh_encrypted_vault("hunter2");
    let input = UnlockWorkerInput {
        path: path.clone(),
        lock: VaultLock::Encrypted(SecretString::from("hunter2".to_string())),
    };

    let completion = run_unlock_worker(input);

    assert!(
        completion.pair.is_some(),
        "Encrypted open with the correct passphrase must carry the live pair forward",
    );
    match completion.effect {
        UnlockWorkerEffect::Success(UnlockSuccessEffect::SetAppState(AppState::Unlocked {
            path: state_path,
        })) => {
            assert_eq!(
                state_path, path,
                "Success effect must carry the input vault path verbatim",
            );
        }
        other => panic!("expected Success(SetAppState(Unlocked)), got {other:?}"),
    }
}

#[test]
fn run_unlock_worker_returns_inline_failure_for_wrong_passphrase() {
    // Wrong-passphrase failures stay inline on the dialog so the
    // user can retype without losing the surface. The worker must
    // surface a `Failure(SendUnlockDialogMsg(OpenFailedInline))`
    // bundle with `pair = None` so `AppModel::update` does not
    // attempt to install a phantom pair.
    use secrecy::SecretString;

    let (_tempdir, path) = persist_fresh_encrypted_vault("hunter2");
    let input = UnlockWorkerInput {
        path: path.clone(),
        lock: VaultLock::Encrypted(SecretString::from("wrong-passphrase".to_string())),
    };

    let completion = run_unlock_worker(input);

    assert!(
        completion.pair.is_none(),
        "Wrong-passphrase failure must not carry a (Vault, Store) pair",
    );
    match completion.effect {
        UnlockWorkerEffect::Failure(UnlockFailureEffect::SendUnlockDialogMsg(
            UnlockDialogMsg::OpenFailedInline(inline),
        )) => {
            assert_eq!(
                inline.kind,
                ErrorKind::DecryptFailed,
                "Encrypted-vault wrong passphrase must surface as DecryptFailed",
            );
            assert!(
                !inline.rendered.is_empty(),
                "expected non-empty inline rendered text",
            );
        }
        other => panic!(
            "expected Failure(SendUnlockDialogMsg(OpenFailedInline(..))) for wrong passphrase, \
             got {other:?}"
        ),
    }
}

#[test]
fn run_unlock_worker_routes_missing_file_to_startup_error_with_no_pair() {
    // Pointing the worker at a non-existent vault file is one of
    // the non-passphrase failure modes. `Store::open` surfaces
    // `io_error { operation: "read_vault_file" }`, which
    // `route_unlock_worker_outcome` routes to
    // `StartupErrorComponent` rather than the inline dialog. The
    // completion carries `pair = None` so the inline / startup
    // partition pinned by `apply_unlock_vault_install_inplace`
    // stays intact.
    let tempdir = tempfile::tempdir().expect("create tempdir for missing-file test");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(tempdir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod tempdir to 0700");
    }
    let missing_path = tempdir.path().join("absent-vault.bin");
    assert!(
        !missing_path.exists(),
        "the missing-file fixture must not pre-create the vault file",
    );

    let input = UnlockWorkerInput {
        path: missing_path.clone(),
        lock: VaultLock::Plaintext,
    };

    let completion = run_unlock_worker(input);

    assert!(
        completion.pair.is_none(),
        "Missing-file failure must not carry a (Vault, Store) pair",
    );
    match completion.effect {
        UnlockWorkerEffect::Failure(UnlockFailureEffect::SetAppState(AppState::StartupError {
            path: Some(state_path),
            ..
        })) => {
            assert_eq!(
                state_path, missing_path,
                "StartupError must retain the failed vault path so retry can re-run from it",
            );
        }
        other => panic!(
            "expected Failure(SetAppState(StartupError {{ path: Some(..) }})) for missing file, \
             got {other:?}"
        ),
    }
}

#[test]
fn run_unlock_worker_success_attaches_caller_provided_path_to_completion_effect() {
    // The worker uses the path carried by the `UnlockWorkerInput`
    // — not whatever `Store::open` would otherwise have known —
    // when routing the outcome. This pins that the completion
    // effect's path mirrors the caller's input so `AppModel::update`
    // can rely on the post-worker `AppState::Unlocked { path }`
    // matching the path it captured pre-spawn via
    // `compose_unlock_worker_input`.
    let (_tempdir, real_path) = persist_fresh_plaintext_vault();
    let input = UnlockWorkerInput {
        path: real_path.clone(),
        lock: VaultLock::Plaintext,
    };

    let completion = run_unlock_worker(input);

    match completion.effect {
        UnlockWorkerEffect::Success(UnlockSuccessEffect::SetAppState(AppState::Unlocked {
            path: state_path,
        })) => {
            assert_eq!(
                state_path, real_path,
                "the success-branch path must come from the input, mirroring \
                 route_unlock_open_completion's path-passthrough contract",
            );
        }
        other => panic!("expected Success(SetAppState(Unlocked)), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Remove state transitions
//
// Mirrors the rename block above for the remove path. The remove
// worker shares the busy-gate semantics (`Unlocked → UnlockedBusy →
// Unlocked`) with the rename worker, so the tests verify the same
// invariants against the remove-side helpers.
// ---------------------------------------------------------------------------

#[test]
fn submit_remove_app_state_from_unlocked_returns_unlocked_busy_preserving_path() {
    use paladin_gtk::app::state::submit_remove_app_state;
    let path = vault_path();
    let unlocked = AppState::Unlocked { path: path.clone() };
    let next = submit_remove_app_state(&unlocked)
        .expect("Unlocked must transition to UnlockedBusy on submit");
    assert!(matches!(next, AppState::UnlockedBusy { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn submit_remove_app_state_from_non_unlocked_returns_none() {
    use paladin_gtk::app::state::submit_remove_app_state;
    let path = vault_path();
    assert!(submit_remove_app_state(&AppState::Missing { path: path.clone() }).is_none());
    assert!(submit_remove_app_state(&AppState::Locked { path: path.clone() }).is_none());
    assert!(submit_remove_app_state(&AppState::UnlockedBusy { path: path.clone() }).is_none());
    let startup = decide_state_from_inspect(&path, Err(invalid_header_err()))
        .expect("inspect Err yields StartupError state");
    assert!(submit_remove_app_state(&startup).is_none());
}

#[test]
fn compose_remove_worker_input_from_unlocked_bundles_pair_and_account_id() {
    use paladin_gtk::app::state::compose_remove_worker_input;
    use paladin_gtk::remove_dialog::RemoveWorkerInput;

    let (_tempdir, path, vault, store) = fresh_plaintext_pair();
    let unlocked = AppState::Unlocked { path: path.clone() };
    let account_id = AccountId::new();

    let input: RemoveWorkerInput =
        compose_remove_worker_input(&unlocked, (vault, store), account_id)
            .expect("Unlocked source must produce a RemoveWorkerInput");

    assert_eq!(input.account_id, account_id);
    assert_eq!(input.vault.summaries().count(), 0);
}

#[test]
fn compose_remove_worker_input_from_non_unlocked_returns_pair_back() {
    use paladin_gtk::app::state::compose_remove_worker_input;
    let account_id = AccountId::new();
    for variant in ["missing", "locked", "unlocked_busy", "startup_error"] {
        let (_tempdir, path, vault, store) = fresh_plaintext_pair();
        let source = match variant {
            "missing" => AppState::Missing { path: path.clone() },
            "locked" => AppState::Locked { path: path.clone() },
            "unlocked_busy" => AppState::UnlockedBusy { path: path.clone() },
            "startup_error" => decide_state_from_inspect(&path, Err(invalid_header_err()))
                .expect("inspect Err yields StartupError state"),
            _ => unreachable!(),
        };
        let result = compose_remove_worker_input(&source, (vault, store), account_id);
        assert!(
            result.is_err(),
            "non-Unlocked source must return Err(pair), variant={variant}",
        );
        let (returned_vault, _returned_store) = result.err().unwrap();
        assert_eq!(returned_vault.summaries().count(), 0);
    }
}

#[test]
fn apply_submit_remove_inplace_from_unlocked_mutates_to_unlocked_busy_and_returns_true() {
    use paladin_gtk::app::state::apply_submit_remove_inplace;
    let path = vault_path();
    let mut state = AppState::Unlocked { path: path.clone() };
    let mutated = apply_submit_remove_inplace(&mut state);
    assert!(mutated);
    assert!(matches!(state, AppState::UnlockedBusy { .. }));
    assert_path_eq(&state, &path);
}

#[test]
fn apply_submit_remove_inplace_from_non_unlocked_leaves_state_unchanged_and_returns_false() {
    use paladin_gtk::app::state::apply_submit_remove_inplace;
    let path = vault_path();
    for variant in ["missing", "locked", "unlocked_busy"] {
        let mut state = match variant {
            "missing" => AppState::Missing { path: path.clone() },
            "locked" => AppState::Locked { path: path.clone() },
            "unlocked_busy" => AppState::UnlockedBusy { path: path.clone() },
            _ => unreachable!(),
        };
        let before = state.clone();
        let mutated = apply_submit_remove_inplace(&mut state);
        assert!(!mutated, "variant={variant}");
        assert_eq!(
            std::mem::discriminant::<AppState>(&before),
            std::mem::discriminant::<AppState>(&state),
            "variant={variant}",
        );
    }
}

#[test]
fn remove_final_app_state_success_rolls_back_to_unlocked_preserving_path() {
    use paladin_gtk::app::state::remove_final_app_state;
    use paladin_gtk::remove_dialog::RemoveWorkerEffect;
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let next = remove_final_app_state(&busy, &RemoveWorkerEffect::Success)
        .expect("UnlockedBusy must roll back to Unlocked");
    assert!(matches!(next, AppState::Unlocked { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn remove_final_app_state_failure_rolls_back_to_unlocked_for_every_outcome() {
    use paladin_gtk::app::state::remove_final_app_state;
    use paladin_gtk::remove_dialog::{
        account_not_found_error, classify_remove_error, RemoveWorkerEffect,
    };
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let effects = [
        RemoveWorkerEffect::Failure(classify_remove_error(&PaladinError::SaveNotCommitted {
            committed: false,
            backup_path: None,
        })),
        RemoveWorkerEffect::Failure(classify_remove_error(
            &PaladinError::SaveDurabilityUnconfirmed,
        )),
        RemoveWorkerEffect::Failure(classify_remove_error(&account_not_found_error())),
    ];
    for effect in &effects {
        let next = remove_final_app_state(&busy, effect)
            .expect("every failure still rolls UnlockedBusy back to Unlocked");
        assert!(matches!(next, AppState::Unlocked { .. }));
        assert_path_eq(&next, &path);
    }
}

#[test]
fn remove_final_app_state_from_non_unlocked_busy_returns_none() {
    use paladin_gtk::app::state::remove_final_app_state;
    use paladin_gtk::remove_dialog::RemoveWorkerEffect;
    let path = vault_path();
    let sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
    ];
    for source in &sources {
        assert!(
            remove_final_app_state(source, &RemoveWorkerEffect::Success).is_none(),
            "source={source:?}",
        );
    }
}

#[test]
fn should_drop_remove_dialog_after_success_returns_true() {
    use paladin_gtk::app::state::should_drop_remove_dialog_after;
    use paladin_gtk::remove_dialog::RemoveWorkerEffect;
    assert!(should_drop_remove_dialog_after(
        &RemoveWorkerEffect::Success
    ));
}

#[test]
fn should_drop_remove_dialog_after_failure_returns_false_for_every_outcome() {
    use paladin_gtk::app::state::should_drop_remove_dialog_after;
    use paladin_gtk::remove_dialog::{
        account_not_found_error, classify_remove_error, RemoveWorkerEffect,
    };
    let effects = [
        RemoveWorkerEffect::Failure(classify_remove_error(&PaladinError::SaveNotCommitted {
            committed: false,
            backup_path: None,
        })),
        RemoveWorkerEffect::Failure(classify_remove_error(
            &PaladinError::SaveDurabilityUnconfirmed,
        )),
        RemoveWorkerEffect::Failure(classify_remove_error(&account_not_found_error())),
    ];
    for effect in &effects {
        assert!(!should_drop_remove_dialog_after(effect));
    }
}

#[test]
fn remove_dialog_msg_after_success_returns_none() {
    use paladin_gtk::app::state::remove_dialog_msg_after;
    use paladin_gtk::remove_dialog::RemoveWorkerEffect;
    assert!(remove_dialog_msg_after(&RemoveWorkerEffect::Success).is_none());
}

#[test]
fn remove_dialog_msg_after_failure_forwards_worker_failed() {
    use paladin_gtk::app::state::remove_dialog_msg_after;
    use paladin_gtk::remove_dialog::{
        classify_remove_error, RemoveDialogMsg, RemoveErrorOutcome, RemoveWorkerEffect,
    };
    let outcome = classify_remove_error(&PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    });
    assert!(matches!(outcome, RemoveErrorOutcome::RestorePrior(_)));
    let effect = RemoveWorkerEffect::Failure(outcome);
    let msg = remove_dialog_msg_after(&effect).expect("Failure forwards a WorkerFailed message");
    assert!(matches!(
        msg,
        RemoveDialogMsg::WorkerFailed(RemoveErrorOutcome::RestorePrior(_))
    ));
}

#[test]
fn remove_dialog_msg_after_is_mutually_exclusive_with_should_drop() {
    use paladin_gtk::app::state::{remove_dialog_msg_after, should_drop_remove_dialog_after};
    use paladin_gtk::remove_dialog::{
        account_not_found_error, classify_remove_error, RemoveWorkerEffect,
    };
    let effects = [
        RemoveWorkerEffect::Success,
        RemoveWorkerEffect::Failure(classify_remove_error(&PaladinError::SaveNotCommitted {
            committed: false,
            backup_path: None,
        })),
        RemoveWorkerEffect::Failure(classify_remove_error(
            &PaladinError::SaveDurabilityUnconfirmed,
        )),
        RemoveWorkerEffect::Failure(classify_remove_error(&account_not_found_error())),
    ];
    for effect in &effects {
        let drop = should_drop_remove_dialog_after(effect);
        let msg = remove_dialog_msg_after(effect);
        assert_eq!(
            msg.is_none(),
            drop,
            "dialog_msg.is_none must equal drop_dialog (effect={effect:?})",
        );
    }
}

#[test]
fn should_refresh_list_after_remove_success_returns_true() {
    use paladin_gtk::app::state::should_refresh_list_after_remove;
    use paladin_gtk::remove_dialog::RemoveWorkerEffect;

    assert!(
        should_refresh_list_after_remove(&RemoveWorkerEffect::Success),
        "Success refreshes the list so the removed row disappears",
    );
}

#[test]
fn should_refresh_list_after_remove_failure_restore_prior_returns_false() {
    use paladin_gtk::app::state::should_refresh_list_after_remove;
    use paladin_gtk::remove_dialog::{
        classify_remove_error, RemoveErrorOutcome, RemoveWorkerEffect,
    };

    let outcome = classify_remove_error(&PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    });
    assert!(matches!(outcome, RemoveErrorOutcome::RestorePrior(_)));
    let effect = RemoveWorkerEffect::Failure(outcome);
    assert!(
        !should_refresh_list_after_remove(&effect),
        "RestorePrior leaves vault state unchanged so no list refresh is needed",
    );
}

#[test]
fn should_refresh_list_after_remove_failure_keep_removed_with_warning_returns_true() {
    use paladin_gtk::app::state::should_refresh_list_after_remove;
    use paladin_gtk::remove_dialog::{
        classify_remove_error, RemoveErrorOutcome, RemoveWorkerEffect,
    };

    let outcome = classify_remove_error(&PaladinError::SaveDurabilityUnconfirmed);
    assert!(matches!(
        outcome,
        RemoveErrorOutcome::KeepRemovedWithWarning(_)
    ));
    let effect = RemoveWorkerEffect::Failure(outcome);
    assert!(
        should_refresh_list_after_remove(&effect),
        "KeepRemovedWithWarning commits the removal in memory; the list must surface it",
    );
}

#[test]
fn should_refresh_list_after_remove_failure_inline_error_returns_false() {
    use paladin_gtk::app::state::should_refresh_list_after_remove;
    use paladin_gtk::remove_dialog::{
        account_not_found_error, classify_remove_error, RemoveErrorOutcome, RemoveWorkerEffect,
    };

    let outcome = classify_remove_error(&account_not_found_error());
    assert!(matches!(outcome, RemoveErrorOutcome::InlineError(_)));
    let effect = RemoveWorkerEffect::Failure(outcome);
    assert!(
        !should_refresh_list_after_remove(&effect),
        "defensive InlineError leaves vault state unchanged so no list refresh is needed",
    );
}

#[test]
fn should_refresh_list_after_remove_partitions_on_committed_outcomes() {
    use paladin_gtk::app::state::should_refresh_list_after_remove;
    use paladin_gtk::remove_dialog::{
        account_not_found_error, classify_remove_error, RemoveWorkerEffect,
    };

    let refresh_effects = [
        RemoveWorkerEffect::Success,
        RemoveWorkerEffect::Failure(classify_remove_error(
            &PaladinError::SaveDurabilityUnconfirmed,
        )),
    ];
    let skip_effects = [
        RemoveWorkerEffect::Failure(classify_remove_error(&PaladinError::SaveNotCommitted {
            committed: false,
            backup_path: None,
        })),
        RemoveWorkerEffect::Failure(classify_remove_error(&PaladinError::SaveNotCommitted {
            committed: true,
            backup_path: None,
        })),
        RemoveWorkerEffect::Failure(classify_remove_error(&account_not_found_error())),
    ];
    for effect in &refresh_effects {
        assert!(
            should_refresh_list_after_remove(effect),
            "refresh partition expects true for effect={effect:?}",
        );
    }
    for effect in &skip_effects {
        assert!(
            !should_refresh_list_after_remove(effect),
            "skip partition expects false for effect={effect:?}",
        );
    }
}

#[test]
fn compose_remove_dispatch_success_bundles_drop_and_unlocked_rollback() {
    use paladin_gtk::app::state::compose_remove_dispatch;
    use paladin_gtk::remove_dialog::RemoveWorkerEffect;
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let dispatch = compose_remove_dispatch(&busy, &RemoveWorkerEffect::Success);
    assert!(dispatch.drop_dialog);
    assert!(dispatch.dialog_msg.is_none());
    assert!(
        dispatch.refresh_list,
        "Success refreshes the list so the removed row disappears",
    );
    let next = dispatch.app_state.expect("Success rolls back to Unlocked");
    assert!(matches!(next, AppState::Unlocked { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn compose_remove_dispatch_failure_keeps_dialog_with_msg_and_unlocked_rollback() {
    use paladin_gtk::app::state::compose_remove_dispatch;
    use paladin_gtk::remove_dialog::{
        classify_remove_error, RemoveDialogMsg, RemoveErrorOutcome, RemoveWorkerEffect,
    };
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let outcome = classify_remove_error(&PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    });
    let effect = RemoveWorkerEffect::Failure(outcome);
    let dispatch = compose_remove_dispatch(&busy, &effect);
    assert!(!dispatch.drop_dialog);
    let msg = dispatch.dialog_msg.as_ref().expect("forwards WorkerFailed");
    assert!(matches!(
        msg,
        RemoveDialogMsg::WorkerFailed(RemoveErrorOutcome::RestorePrior(_))
    ));
    assert!(
        !dispatch.refresh_list,
        "RestorePrior leaves vault state unchanged so no list refresh is needed",
    );
    let next = dispatch
        .app_state
        .expect("Failure still rolls UnlockedBusy back to Unlocked");
    assert!(matches!(next, AppState::Unlocked { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn compose_remove_dispatch_from_non_unlocked_busy_returns_no_app_state() {
    use paladin_gtk::app::state::compose_remove_dispatch;
    use paladin_gtk::remove_dialog::RemoveWorkerEffect;
    let path = vault_path();
    let sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
    ];
    for source in &sources {
        let dispatch = compose_remove_dispatch(source, &RemoveWorkerEffect::Success);
        assert!(dispatch.app_state.is_none(), "source={source:?}");
        assert!(
            dispatch.drop_dialog,
            "drop_dialog still mirrors should_drop_remove_dialog_after",
        );
    }
}

// ---------------------------------------------------------------------------
// remove_success_toast_after — toast-body projection for the remove worker
// outcome. `AppMsg::RemoveWorkerCompleted` consults this to decide whether
// to raise an `AdwToast` on the `adw::ToastOverlay` per
// `IMPLEMENTATION_PLAN_04_GTK.md` §"Milestone 7 checklist" > `RemoveDialog`
// confirmation flow ("On success, refresh `AccountListComponent` from the
// returned vault, close the dialog, and surface a status / toast
// confirmation."). The projection inspects only the typed
// `RemoveWorkerEffect` variant so the side-effect decision in
// `AppModel::update` stays unit-testable without spinning up GTK /
// libadwaita.
// ---------------------------------------------------------------------------

#[test]
fn remove_success_toast_after_success_returns_body() {
    use paladin_gtk::app::state::remove_success_toast_after;
    use paladin_gtk::remove_dialog::{format_remove_dialog_success_toast, RemoveWorkerEffect};

    let toast = remove_success_toast_after(&RemoveWorkerEffect::Success)
        .expect("Success must surface a confirmation toast");
    assert_eq!(
        toast,
        format_remove_dialog_success_toast(),
        "toast body must come from format_remove_dialog_success_toast so wording stays single-sourced",
    );
}

#[test]
fn remove_success_toast_after_failure_returns_none() {
    use paladin_gtk::app::state::remove_success_toast_after;
    use paladin_gtk::remove_dialog::{
        account_not_found_error, classify_remove_error, RemoveWorkerEffect,
    };

    let failures = [
        PaladinError::SaveNotCommitted {
            committed: false,
            backup_path: None,
        },
        PaladinError::SaveNotCommitted {
            committed: true,
            backup_path: None,
        },
        PaladinError::SaveDurabilityUnconfirmed,
        account_not_found_error(),
    ];
    for err in &failures {
        let outcome = classify_remove_error(err);
        let effect = RemoveWorkerEffect::Failure(outcome);
        assert!(
            remove_success_toast_after(&effect).is_none(),
            "Failure must not raise a success toast for err={err:?}",
        );
    }
}

#[test]
fn compose_remove_dispatch_populates_success_toast_only_on_success() {
    // `compose_remove_dispatch` bundles `remove_success_toast_after`
    // alongside the existing drop-dialog / refresh-list / dialog-msg /
    // app-state decisions so the dispatch site can raise the toast in
    // one shot. The success branch carries the toast body so the
    // widget layer just adds it as an `adw::Toast::new(&body)`; the
    // failure branches stay `None` so the dialog's inline error /
    // warning is the only surface that conveys the typed outcome.
    use paladin_gtk::app::state::{compose_remove_dispatch, remove_success_toast_after};
    use paladin_gtk::remove_dialog::{
        account_not_found_error, classify_remove_error, RemoveWorkerEffect,
    };

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let effects = [
        RemoveWorkerEffect::Success,
        RemoveWorkerEffect::Failure(classify_remove_error(&PaladinError::SaveNotCommitted {
            committed: false,
            backup_path: None,
        })),
        RemoveWorkerEffect::Failure(classify_remove_error(
            &PaladinError::SaveDurabilityUnconfirmed,
        )),
        RemoveWorkerEffect::Failure(classify_remove_error(&account_not_found_error())),
    ];
    for effect in &effects {
        let dispatch = compose_remove_dispatch(&busy, effect);
        assert_eq!(
            dispatch.success_toast,
            remove_success_toast_after(effect),
            "success_toast must mirror the projection for effect={effect:?}",
        );
    }
}

#[test]
fn apply_remove_dispatch_inplace_success_rolls_back_to_unlocked_and_returns_true() {
    use paladin_gtk::app::state::{apply_remove_dispatch_inplace, compose_remove_dispatch};
    use paladin_gtk::remove_dialog::RemoveWorkerEffect;
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let dispatch = compose_remove_dispatch(&busy, &RemoveWorkerEffect::Success);
    let mut state = busy.clone();
    let mutated = apply_remove_dispatch_inplace(&mut state, &dispatch);
    assert!(mutated);
    assert!(matches!(state, AppState::Unlocked { .. }));
    assert_path_eq(&state, &path);
}

#[test]
fn apply_remove_dispatch_inplace_from_non_unlocked_busy_leaves_state_unchanged_and_returns_false() {
    use paladin_gtk::app::state::{apply_remove_dispatch_inplace, compose_remove_dispatch};
    use paladin_gtk::remove_dialog::RemoveWorkerEffect;
    let path = vault_path();
    let mut state = AppState::Unlocked { path: path.clone() };
    let dispatch = compose_remove_dispatch(&state, &RemoveWorkerEffect::Success);
    let mutated = apply_remove_dispatch_inplace(&mut state, &dispatch);
    assert!(!mutated);
    assert!(matches!(state, AppState::Unlocked { .. }));
}

#[test]
fn apply_remove_vault_install_inplace_writes_pair_into_empty_slot() {
    use paladin_gtk::app::state::apply_remove_vault_install_inplace;
    let (_tempdir, _path, vault, store) = fresh_plaintext_pair();
    let mut slot: Option<(Vault, Store)> = None;
    apply_remove_vault_install_inplace(&mut slot, (vault, store));
    assert!(slot.is_some());
}

#[test]
fn apply_remove_vault_install_inplace_replaces_existing_slot() {
    use paladin_gtk::app::state::apply_remove_vault_install_inplace;
    let (_tempdir1, _p1, vault1, store1) = fresh_plaintext_pair();
    let (_tempdir2, _p2, vault2, store2) = fresh_plaintext_pair();
    let mut slot: Option<(Vault, Store)> = Some((vault1, store1));
    apply_remove_vault_install_inplace(&mut slot, (vault2, store2));
    assert!(slot.is_some());
}

// ---------------------------------------------------------------------------
// should_drop_add_dialog_after — drop-decision projection
// ---------------------------------------------------------------------------
//
// Symmetric partner of `should_drop_rename_dialog_after` for the
// add path. `AppMsg::AddWorkerCompleted` consults this to decide
// whether to detach the live `AddAccountComponent` from the
// content tree after applying the worker outcome:
//
// * `Success { account_id }` → drop (the dialog dismisses itself
//   and the new row appears in the visible account list).
// * `Failure(AddPostEffectOutcome::Inline)` → stay mounted (the
//   vault was not mutated and the dialog surfaces the inline
//   error so the user can retry).
// * `Failure(AddPostEffectOutcome::KeepWithWarning)` → stay
//   mounted (the new account committed to disk but the parent-
//   directory `fsync` failed; the dialog body attaches the
//   durability warning so the user sees it before dismissing).
//
// The projection inspects only the typed `AddWorkerEffect`
// variant — it does not consult `AppState`, the live `(Vault,
// Store)` pair, or any `AddAccountComponent` state — so the
// side-effect decision in `AppModel::update` stays unit-testable
// without spinning up GTK / libadwaita.

#[test]
fn should_drop_add_dialog_after_success_returns_true() {
    use paladin_core::AccountId;
    use paladin_gtk::add_account::AddWorkerEffect;
    use paladin_gtk::app::state::should_drop_add_dialog_after;

    let effect = AddWorkerEffect::Success {
        account_id: AccountId::new(),
    };
    assert!(
        should_drop_add_dialog_after(&effect),
        "Success must drop the add dialog so the new row appears and the dialog dismisses",
    );
}

#[test]
fn should_drop_add_dialog_after_failure_inline_returns_false() {
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddPostEffectOutcome, AddWorkerEffect,
    };
    use paladin_gtk::app::state::should_drop_add_dialog_after;

    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let outcome = classify_add_post_effect_error(&err);
    assert!(
        matches!(outcome, AddPostEffectOutcome::Inline(_)),
        "save_not_committed routes to Inline",
    );
    let effect = AddWorkerEffect::Failure(outcome);
    assert!(
        !should_drop_add_dialog_after(&effect),
        "Inline failure keeps the dialog mounted so the inline error is visible",
    );
}

#[test]
fn should_drop_add_dialog_after_failure_keep_with_warning_returns_false() {
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddPostEffectOutcome, AddWorkerEffect,
    };
    use paladin_gtk::app::state::should_drop_add_dialog_after;

    let err = PaladinError::SaveDurabilityUnconfirmed;
    let outcome = classify_add_post_effect_error(&err);
    assert!(
        matches!(outcome, AddPostEffectOutcome::KeepWithWarning(_)),
        "save_durability_unconfirmed routes to KeepWithWarning",
    );
    let effect = AddWorkerEffect::Failure(outcome);
    assert!(
        !should_drop_add_dialog_after(&effect),
        "KeepWithWarning keeps the dialog mounted so the durability warning attaches to the body",
    );
}

#[test]
fn should_drop_add_dialog_after_failure_defensive_inline_returns_false() {
    // Defensive: `invalid_state` would only fire if the
    // `Vault::mutate_and_save` closure observed an unexpected
    // post-condition. `classify_add_post_effect_error` routes it
    // to `Inline`, so the dialog stays mounted.
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddPostEffectOutcome, AddWorkerEffect,
    };
    use paladin_gtk::app::state::should_drop_add_dialog_after;

    let err = PaladinError::InvalidState {
        operation: "add",
        state: "account_not_found",
    };
    let outcome = classify_add_post_effect_error(&err);
    assert!(
        matches!(outcome, AddPostEffectOutcome::Inline(_)),
        "defensive invalid_state routes to Inline",
    );
    let effect = AddWorkerEffect::Failure(outcome);
    assert!(
        !should_drop_add_dialog_after(&effect),
        "defensive Inline keeps the dialog mounted so the typed error is visible",
    );
}

#[test]
fn should_drop_add_dialog_after_partitions_on_success_only() {
    // Cross-check: the projection partitions effects into "drop"
    // (Success only) and "keep" (every Failure variant). Pin the
    // partition across every typed outcome so a future routing
    // refinement that swaps a Failure branch into the drop side
    // (or vice versa) is caught here.
    use paladin_core::AccountId;
    use paladin_gtk::add_account::{classify_add_post_effect_error, AddWorkerEffect};
    use paladin_gtk::app::state::should_drop_add_dialog_after;

    let drop_effects = [AddWorkerEffect::Success {
        account_id: AccountId::new(),
    }];
    let keep_effects = [
        AddWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::SaveNotCommitted {
                committed: false,
                backup_path: None,
            },
        )),
        AddWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::SaveNotCommitted {
                committed: true,
                backup_path: None,
            },
        )),
        AddWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::SaveDurabilityUnconfirmed,
        )),
        AddWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::InvalidState {
                operation: "add",
                state: "account_not_found",
            },
        )),
    ];
    for effect in &drop_effects {
        assert!(
            should_drop_add_dialog_after(effect),
            "drop partition expects true for effect={effect:?}",
        );
    }
    for effect in &keep_effects {
        assert!(
            !should_drop_add_dialog_after(effect),
            "keep partition expects false for effect={effect:?}",
        );
    }
}

// ---------------------------------------------------------------------------
// should_refresh_list_after_add — list-refresh decision projection
// ---------------------------------------------------------------------------
//
// `AppMsg::AddWorkerCompleted` consults this to decide whether to
// re-project rows off the freshly reinstalled `(Vault, Store)` pair
// and emit `AccountListMsg::Refresh` so the new account appears in
// the visible row set per `IMPLEMENTATION_PLAN_04_GTK.md`
// §"Component tree" > `AccountListComponent` ("Refresh the store
// after every vault mutation … without reordering surviving rows"):
//
// * `Success` → `true`. The add committed and the new row must
//   surface in the list.
// * `Failure(AddPostEffectOutcome::Inline)` → `false`.
//   `Vault::mutate_and_save` rolled back (`save_not_committed`,
//   `io_error`) or never mutated (defensive
//   `validation_error` / `invalid_state`); the visible rows
//   already match the post-rollback state.
// * `Failure(AddPostEffectOutcome::KeepWithWarning)` → `true`.
//   Primary save succeeded so the new account is durable in
//   memory; the list must surface it even though the parent
//   fsync was uncertain.

#[test]
fn should_refresh_list_after_add_success_returns_true() {
    use paladin_core::AccountId;
    use paladin_gtk::add_account::AddWorkerEffect;
    use paladin_gtk::app::state::should_refresh_list_after_add;

    let effect = AddWorkerEffect::Success {
        account_id: AccountId::new(),
    };
    assert!(
        should_refresh_list_after_add(&effect),
        "Success refreshes the list so the new row appears",
    );
}

#[test]
fn should_refresh_list_after_add_failure_inline_returns_false() {
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddPostEffectOutcome, AddWorkerEffect,
    };
    use paladin_gtk::app::state::should_refresh_list_after_add;

    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let outcome = classify_add_post_effect_error(&err);
    assert!(
        matches!(outcome, AddPostEffectOutcome::Inline(_)),
        "save_not_committed routes to Inline",
    );
    let effect = AddWorkerEffect::Failure(outcome);
    assert!(
        !should_refresh_list_after_add(&effect),
        "Inline failure leaves vault state unchanged so no list refresh is needed",
    );
}

#[test]
fn should_refresh_list_after_add_failure_keep_with_warning_returns_true() {
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddPostEffectOutcome, AddWorkerEffect,
    };
    use paladin_gtk::app::state::should_refresh_list_after_add;

    let err = PaladinError::SaveDurabilityUnconfirmed;
    let outcome = classify_add_post_effect_error(&err);
    assert!(
        matches!(outcome, AddPostEffectOutcome::KeepWithWarning(_)),
        "save_durability_unconfirmed routes to KeepWithWarning",
    );
    let effect = AddWorkerEffect::Failure(outcome);
    assert!(
        should_refresh_list_after_add(&effect),
        "KeepWithWarning commits the new account in memory; the list must surface it",
    );
}

#[test]
fn should_refresh_list_after_add_failure_defensive_inline_returns_false() {
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddPostEffectOutcome, AddWorkerEffect,
    };
    use paladin_gtk::app::state::should_refresh_list_after_add;

    let err = PaladinError::InvalidState {
        operation: "add",
        state: "account_not_found",
    };
    let outcome = classify_add_post_effect_error(&err);
    assert!(
        matches!(outcome, AddPostEffectOutcome::Inline(_)),
        "defensive invalid_state routes to Inline",
    );
    let effect = AddWorkerEffect::Failure(outcome);
    assert!(
        !should_refresh_list_after_add(&effect),
        "defensive Inline leaves vault state unchanged so no list refresh is needed",
    );
}

#[test]
fn should_refresh_list_after_add_partitions_on_committed_outcomes() {
    use paladin_core::AccountId;
    use paladin_gtk::add_account::{classify_add_post_effect_error, AddWorkerEffect};
    use paladin_gtk::app::state::should_refresh_list_after_add;

    let refresh_effects = [
        AddWorkerEffect::Success {
            account_id: AccountId::new(),
        },
        AddWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::SaveDurabilityUnconfirmed,
        )),
    ];
    let skip_effects = [
        AddWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::SaveNotCommitted {
                committed: false,
                backup_path: None,
            },
        )),
        AddWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::SaveNotCommitted {
                committed: true,
                backup_path: None,
            },
        )),
        AddWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::InvalidState {
                operation: "add",
                state: "account_not_found",
            },
        )),
    ];
    for effect in &refresh_effects {
        assert!(
            should_refresh_list_after_add(effect),
            "refresh partition expects true for effect={effect:?}",
        );
    }
    for effect in &skip_effects {
        assert!(
            !should_refresh_list_after_add(effect),
            "skip partition expects false for effect={effect:?}",
        );
    }
}

// ---------------------------------------------------------------------------
// add_dialog_msg_after — inline-message projection
// ---------------------------------------------------------------------------
//
// Symmetric partner of `rename_dialog_msg_after` for the add path.
// `AppMsg::AddWorkerCompleted` consults this to decide what message
// (if any) to forward into the live `AddAccountComponent` after
// applying the worker outcome:
//
// * `Success` → `None`. The dialog is being dropped — there is no
//   live controller to forward to.
// * `Failure(outcome)` → `Some(AddAccountMsg::WorkerFailed(
//   outcome.clone()))`. The dialog stays mounted; the message
//   carries the typed `AddPostEffectOutcome` so the dialog can
//   route `Inline` (render the typed inline error and keep the
//   form populated for retry) or `KeepWithWarning` (attach the
//   durability warning to the body) without re-deriving the
//   routing off the `PaladinError`.
//
// The projection returns an *owned* `Option<AddAccountMsg>` rather
// than a borrow into the effect because `AddWorkerEffect` carries
// the typed `AddPostEffectOutcome` rather than a pre-built dialog
// message. The clone is cheap — the outcome only holds an
// `InlineError` / `InlineWarning` struct of an `ErrorKind` and a
// `String` body.
//
// The projection inspects only the typed `AddWorkerEffect`
// variant — it does not consult `AppState`, the live `(Vault,
// Store)` pair, or any `AddAccountComponent` state — so the
// side-effect decision in `AppModel::update` stays unit-testable
// without spinning up GTK / libadwaita.

#[test]
fn add_dialog_msg_after_success_returns_none() {
    use paladin_core::AccountId;
    use paladin_gtk::add_account::AddWorkerEffect;
    use paladin_gtk::app::state::add_dialog_msg_after;

    let effect = AddWorkerEffect::Success {
        account_id: AccountId::new(),
    };
    assert!(
        add_dialog_msg_after(&effect).is_none(),
        "Success drops the dialog, so no inline message is forwarded",
    );
}

#[test]
fn add_dialog_msg_after_failure_inline_forwards_worker_failed_with_outcome() {
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddAccountMsg, AddPostEffectOutcome, AddWorkerEffect,
    };
    use paladin_gtk::app::state::add_dialog_msg_after;

    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let outcome = classify_add_post_effect_error(&err);
    assert!(
        matches!(outcome, AddPostEffectOutcome::Inline(_)),
        "save_not_committed routes to Inline",
    );
    let effect = AddWorkerEffect::Failure(outcome);
    let msg = add_dialog_msg_after(&effect)
        .expect("Failure forwards a WorkerFailed message so the dialog stays mounted");
    let AddAccountMsg::WorkerFailed(forwarded) = msg else {
        panic!("expected AddAccountMsg::WorkerFailed for a Failure outcome");
    };
    match forwarded {
        AddPostEffectOutcome::Inline(inline) => assert_eq!(
            inline.kind,
            ErrorKind::SaveNotCommitted,
            "Inline must round-trip the SaveNotCommitted ErrorKind",
        ),
        AddPostEffectOutcome::KeepWithWarning(warning) => {
            panic!("expected WorkerFailed(Inline), got WorkerFailed(KeepWithWarning({warning:?}))")
        }
    }
}

#[test]
fn add_dialog_msg_after_failure_keep_with_warning_forwards_worker_failed_with_outcome() {
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddAccountMsg, AddPostEffectOutcome, AddWorkerEffect,
    };
    use paladin_gtk::app::state::add_dialog_msg_after;

    let err = PaladinError::SaveDurabilityUnconfirmed;
    let outcome = classify_add_post_effect_error(&err);
    assert!(
        matches!(outcome, AddPostEffectOutcome::KeepWithWarning(_)),
        "save_durability_unconfirmed routes to KeepWithWarning",
    );
    let effect = AddWorkerEffect::Failure(outcome);
    let msg = add_dialog_msg_after(&effect)
        .expect("Failure forwards a WorkerFailed message so the dialog stays mounted");
    let AddAccountMsg::WorkerFailed(forwarded) = msg else {
        panic!("expected AddAccountMsg::WorkerFailed for a Failure outcome");
    };
    match forwarded {
        AddPostEffectOutcome::KeepWithWarning(warning) => assert_eq!(
            warning.kind,
            ErrorKind::SaveDurabilityUnconfirmed,
            "KeepWithWarning must round-trip the SaveDurabilityUnconfirmed ErrorKind",
        ),
        AddPostEffectOutcome::Inline(inline) => {
            panic!("expected WorkerFailed(KeepWithWarning), got WorkerFailed(Inline({inline:?}))")
        }
    }
}

#[test]
fn add_dialog_msg_after_failure_defensive_inline_forwards_worker_failed_with_outcome() {
    // Defensive: a `validation_error` / `invalid_state` from
    // `Vault::mutate_and_save` rolls back the snapshot and routes
    // through `classify_add_post_effect_error` to the `Inline`
    // arm. Pin the message-forwarding contract for the defensive
    // branch so the dialog can render the typed error without
    // re-deriving the routing.
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddAccountMsg, AddPostEffectOutcome, AddWorkerEffect,
    };
    use paladin_gtk::app::state::add_dialog_msg_after;

    let err = PaladinError::InvalidState {
        operation: "add",
        state: "account_not_found",
    };
    let outcome = classify_add_post_effect_error(&err);
    assert!(
        matches!(outcome, AddPostEffectOutcome::Inline(_)),
        "defensive invalid_state routes to Inline",
    );
    let effect = AddWorkerEffect::Failure(outcome);
    let msg = add_dialog_msg_after(&effect)
        .expect("Failure forwards a WorkerFailed message so the dialog stays mounted");
    let AddAccountMsg::WorkerFailed(forwarded) = msg else {
        panic!("expected AddAccountMsg::WorkerFailed for a Failure outcome");
    };
    match forwarded {
        AddPostEffectOutcome::Inline(inline) => assert_eq!(
            inline.kind,
            ErrorKind::InvalidState,
            "defensive Inline must round-trip the InvalidState ErrorKind",
        ),
        AddPostEffectOutcome::KeepWithWarning(warning) => panic!(
            "expected defensive WorkerFailed(Inline), got WorkerFailed(KeepWithWarning({warning:?}))"
        ),
    }
}

#[test]
fn add_dialog_msg_after_is_mutually_exclusive_with_should_drop() {
    // Cross-check: the inline-message projection must report `Some`
    // exactly when `should_drop_add_dialog_after` reports `false`
    // (dialog stays mounted), and `None` when the dispatch drops
    // the dialog. Pinned across every typed effect so the two
    // projections can't drift apart silently — a future routing
    // refinement that puts a Failure variant on the drop side
    // would need to update both helpers in lockstep, and this
    // test catches the partial update.
    use paladin_core::AccountId;
    use paladin_gtk::add_account::{classify_add_post_effect_error, AddWorkerEffect};
    use paladin_gtk::app::state::{add_dialog_msg_after, should_drop_add_dialog_after};

    let effects = [
        AddWorkerEffect::Success {
            account_id: AccountId::new(),
        },
        AddWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::SaveNotCommitted {
                committed: false,
                backup_path: None,
            },
        )),
        AddWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::SaveNotCommitted {
                committed: true,
                backup_path: None,
            },
        )),
        AddWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::SaveDurabilityUnconfirmed,
        )),
        AddWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::InvalidState {
                operation: "add",
                state: "account_not_found",
            },
        )),
    ];
    for effect in &effects {
        let drops = should_drop_add_dialog_after(effect);
        let msg = add_dialog_msg_after(effect);
        assert_eq!(
            drops,
            msg.is_none(),
            "drop/keep partition must match Some/None partition for effect={effect:?} \
             (drops={drops}, msg.is_some()={})",
            msg.is_some(),
        );
    }
}

// ---------------------------------------------------------------------------
// add_success_toast_after — toast-body projection for the add worker outcome.
// ---------------------------------------------------------------------------
//
// `AppMsg::AddWorkerCompleted` consults this to decide whether to
// raise an `AdwToast` on the `adw::ToastOverlay` per
// `IMPLEMENTATION_PLAN_04_GTK.md` §"Milestone 7 checklist" >
// `AddAccountComponent` shared shell ("Keep successful manual and URI
// additions consistent with §7: refresh the list from the returned
// vault, close the dialog, and surface a status / toast confirmation.").
// The projection inspects only the typed `AddWorkerEffect` variant so
// the side-effect decision in `AppModel::update` stays unit-testable
// in `tests/app_state_logic.rs` without spinning up GTK / libadwaita.
// Sibling of `rename_success_toast_after` / `remove_success_toast_after`.

#[test]
fn add_success_toast_after_success_returns_body() {
    use paladin_gtk::add_account::{format_add_dialog_success_toast, AddWorkerEffect};
    use paladin_gtk::app::state::add_success_toast_after;

    let effect = AddWorkerEffect::Success {
        account_id: AccountId::new(),
    };
    let toast =
        add_success_toast_after(&effect).expect("Success must surface a confirmation toast");
    assert_eq!(
        toast,
        format_add_dialog_success_toast(),
        "toast body must come from format_add_dialog_success_toast so wording stays single-sourced",
    );
}

#[test]
fn add_success_toast_after_failure_returns_none() {
    use paladin_gtk::add_account::{classify_add_post_effect_error, AddWorkerEffect};
    use paladin_gtk::app::state::add_success_toast_after;

    let failures = [
        PaladinError::SaveNotCommitted {
            committed: false,
            backup_path: None,
        },
        PaladinError::SaveNotCommitted {
            committed: true,
            backup_path: None,
        },
        PaladinError::SaveDurabilityUnconfirmed,
        PaladinError::InvalidState {
            operation: "add",
            state: "duplicate_account",
        },
    ];
    for err in &failures {
        let outcome = classify_add_post_effect_error(err);
        let effect = AddWorkerEffect::Failure(outcome);
        assert!(
            add_success_toast_after(&effect).is_none(),
            "Failure must not raise a success toast for err={err:?}",
        );
    }
}

#[test]
fn compose_add_dispatch_populates_success_toast_only_on_success() {
    // `compose_add_dispatch` bundles `add_success_toast_after` alongside
    // the existing drop-dialog / refresh-list / dialog-msg / app-state
    // decisions so the dispatch site can raise the toast in one shot.
    // The success branch carries the toast body so the widget layer
    // just adds it as an `adw::Toast::new(&body)`; the failure branches
    // stay `None` so the dialog's inline error / body warning is the
    // only surface that conveys the typed outcome.
    use paladin_gtk::add_account::{classify_add_post_effect_error, AddWorkerEffect};
    use paladin_gtk::app::state::{add_success_toast_after, compose_add_dispatch};

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let effects = [
        AddWorkerEffect::Success {
            account_id: AccountId::new(),
        },
        AddWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::SaveNotCommitted {
                committed: false,
                backup_path: None,
            },
        )),
        AddWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::SaveDurabilityUnconfirmed,
        )),
        AddWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::InvalidState {
                operation: "add",
                state: "duplicate_account",
            },
        )),
    ];
    for effect in &effects {
        let dispatch = compose_add_dispatch(&busy, effect);
        assert_eq!(
            dispatch.success_toast,
            add_success_toast_after(effect),
            "success_toast must mirror the projection for effect={effect:?}",
        );
    }
}

// ---------------------------------------------------------------------------
// compose_add_dispatch — bundling composer for the add worker outcome
// ---------------------------------------------------------------------------
//
// Symmetric partner of `compose_rename_dispatch` for the add path.
// Bundles the trio of add-dispatch decisions (`add_final_app_state`,
// `add_dialog_msg_after`, `should_drop_add_dialog_after`) into a
// single `AddDispatch` value so `AppModel::update` can apply the
// worker outcome in one shot.
//
// Invariants pinned at the trio level carry through:
//
// * `drop_dialog == true` iff the worker outcome is
//   `AddWorkerEffect::Success` — the dialog drops on success and
//   stays mounted on every `Failure(AddPostEffectOutcome)` variant.
// * `dialog_msg.is_some() == !drop_dialog`: a dropped dialog gets no
//   inline message; a mounted dialog gets a `WorkerFailed(outcome)`.
// * For the failure branches from a non-`UnlockedBusy` source state
//   (a stray dispatch), `app_state` is `None` while `dialog_msg` and
//   `drop_dialog` still mirror the trio.

#[test]
fn compose_add_dispatch_success_bundles_drop_and_unlocked_rollback() {
    use paladin_gtk::add_account::AddWorkerEffect;
    use paladin_gtk::app::state::compose_add_dispatch;

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let effect = AddWorkerEffect::Success {
        account_id: AccountId::new(),
    };
    let dispatch = compose_add_dispatch(&busy, &effect);
    assert!(
        dispatch.drop_dialog,
        "Success drops the AddAccountComponent so the new row appears and the dialog dismisses",
    );
    assert!(
        dispatch.dialog_msg.is_none(),
        "Success drops the dialog, so no inline message is forwarded",
    );
    let next = dispatch
        .app_state
        .expect("Success rolls UnlockedBusy back to Unlocked");
    assert!(
        matches!(next, AppState::Unlocked { .. }),
        "Success rollback target must be Unlocked, got {next:?}",
    );
    assert_path_eq(&next, &path);
}

#[test]
fn compose_add_dispatch_failure_inline_keeps_dialog_with_msg_and_unlocked_rollback() {
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddAccountMsg, AddPostEffectOutcome, AddWorkerEffect,
    };
    use paladin_gtk::app::state::compose_add_dispatch;

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let outcome = classify_add_post_effect_error(&err);
    assert!(matches!(outcome, AddPostEffectOutcome::Inline(_)));
    let effect = AddWorkerEffect::Failure(outcome);
    let dispatch = compose_add_dispatch(&busy, &effect);
    assert!(
        !dispatch.drop_dialog,
        "Inline failure keeps the AddAccountComponent mounted so the inline error is visible",
    );
    let msg = dispatch
        .dialog_msg
        .as_ref()
        .expect("Inline failure forwards a WorkerFailed message");
    assert!(
        matches!(
            msg,
            AddAccountMsg::WorkerFailed(AddPostEffectOutcome::Inline(_))
        ),
        "Inline failure must forward WorkerFailed(Inline), got {msg:?}",
    );
    let next = dispatch
        .app_state
        .expect("Failure still rolls UnlockedBusy back to Unlocked");
    assert!(matches!(next, AppState::Unlocked { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn compose_add_dispatch_failure_keep_with_warning_keeps_dialog_with_msg_and_unlocked_rollback() {
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddAccountMsg, AddPostEffectOutcome, AddWorkerEffect,
    };
    use paladin_gtk::app::state::compose_add_dispatch;

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = PaladinError::SaveDurabilityUnconfirmed;
    let outcome = classify_add_post_effect_error(&err);
    assert!(matches!(outcome, AddPostEffectOutcome::KeepWithWarning(_)));
    let effect = AddWorkerEffect::Failure(outcome);
    let dispatch = compose_add_dispatch(&busy, &effect);
    assert!(
        !dispatch.drop_dialog,
        "KeepWithWarning keeps the AddAccountComponent mounted so the warning attaches to the body",
    );
    let msg = dispatch
        .dialog_msg
        .as_ref()
        .expect("KeepWithWarning forwards a WorkerFailed message");
    assert!(matches!(
        msg,
        AddAccountMsg::WorkerFailed(AddPostEffectOutcome::KeepWithWarning(_)),
    ));
    let next = dispatch
        .app_state
        .expect("Failure still rolls UnlockedBusy back to Unlocked");
    assert!(matches!(next, AppState::Unlocked { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn compose_add_dispatch_failure_defensive_inline_keeps_dialog_with_msg_and_unlocked_rollback() {
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddAccountMsg, AddPostEffectOutcome, AddWorkerEffect,
    };
    use paladin_gtk::app::state::compose_add_dispatch;

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = PaladinError::InvalidState {
        operation: "add",
        state: "duplicate_account",
    };
    let outcome = classify_add_post_effect_error(&err);
    assert!(
        matches!(outcome, AddPostEffectOutcome::Inline(_)),
        "defensive invalid_state routes to Inline",
    );
    let effect = AddWorkerEffect::Failure(outcome);
    let dispatch = compose_add_dispatch(&busy, &effect);
    assert!(
        !dispatch.drop_dialog,
        "defensive Inline keeps the AddAccountComponent mounted so the typed error is visible",
    );
    let msg = dispatch
        .dialog_msg
        .as_ref()
        .expect("defensive Inline forwards a WorkerFailed message");
    assert!(matches!(
        msg,
        AddAccountMsg::WorkerFailed(AddPostEffectOutcome::Inline(_)),
    ));
    let next = dispatch
        .app_state
        .expect("Failure still rolls UnlockedBusy back to Unlocked");
    assert!(matches!(next, AppState::Unlocked { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn compose_add_dispatch_mirrors_trio_for_every_effect() {
    use paladin_gtk::add_account::{classify_add_post_effect_error, AddWorkerEffect};
    use paladin_gtk::app::state::{
        add_dialog_msg_after, add_final_app_state, compose_add_dispatch,
        should_drop_add_dialog_after, should_refresh_list_after_add,
    };

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let effects = [
        AddWorkerEffect::Success {
            account_id: AccountId::new(),
        },
        AddWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::SaveNotCommitted {
                committed: false,
                backup_path: None,
            },
        )),
        AddWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::SaveNotCommitted {
                committed: true,
                backup_path: None,
            },
        )),
        AddWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::SaveDurabilityUnconfirmed,
        )),
        AddWorkerEffect::Failure(classify_add_post_effect_error(
            &PaladinError::InvalidState {
                operation: "add",
                state: "duplicate_account",
            },
        )),
    ];
    for effect in &effects {
        let dispatch = compose_add_dispatch(&busy, effect);
        assert_eq!(
            dispatch.drop_dialog,
            should_drop_add_dialog_after(effect),
            "drop_dialog must mirror the trio for effect={effect:?}",
        );
        assert_eq!(
            dispatch.refresh_list,
            should_refresh_list_after_add(effect),
            "refresh_list must mirror the helper for effect={effect:?}",
        );
        let trio_msg = add_dialog_msg_after(effect);
        match (&dispatch.dialog_msg, &trio_msg) {
            (None, None) | (Some(_), Some(_)) => {}
            other => panic!(
                "dialog_msg Some/None must mirror the trio for effect={effect:?}, got {other:?}",
            ),
        }
        let trio_state = add_final_app_state(&busy, effect);
        match (&dispatch.app_state, &trio_state) {
            (None, None) => {}
            (Some(a), Some(b)) => {
                assert_eq!(
                    std::mem::discriminant::<AppState>(a),
                    std::mem::discriminant::<AppState>(b),
                    "app_state variant must mirror the trio for effect={effect:?}",
                );
                assert_eq!(
                    a.path().map(Path::to_path_buf),
                    b.path().map(Path::to_path_buf),
                    "app_state path must mirror the trio for effect={effect:?}",
                );
            }
            other => panic!(
                "app_state Some/None must mirror the trio for effect={effect:?}, got {other:?}",
            ),
        }
    }
}

#[test]
fn compose_add_dispatch_from_non_unlocked_busy_returns_no_app_state() {
    // Defensive: when the add worker returns but `current` is not
    // `UnlockedBusy` (a stray dispatch from any other source state),
    // the composer mirrors `add_final_app_state` and reports
    // `app_state = None`. `drop_dialog` and `dialog_msg` still mirror
    // the trio because they inspect only the typed effect — the
    // worker outcome is visible to the dialog regardless of the
    // source state.
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddAccountMsg, AddPostEffectOutcome, AddWorkerEffect,
    };
    use paladin_gtk::app::state::compose_add_dispatch;

    let path = vault_path();
    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let outcome = classify_add_post_effect_error(&err);
    assert!(matches!(outcome, AddPostEffectOutcome::Inline(_)));
    let effect = AddWorkerEffect::Failure(outcome);
    let invalid_sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
    ];
    for source in &invalid_sources {
        let dispatch = compose_add_dispatch(source, &effect);
        assert!(
            !dispatch.drop_dialog,
            "Failure keeps the dialog mounted regardless of source={source:?}",
        );
        assert!(
            matches!(
                dispatch.dialog_msg.as_ref(),
                Some(AddAccountMsg::WorkerFailed(AddPostEffectOutcome::Inline(_))),
            ),
            "Failure forwards WorkerFailed regardless of source={source:?}",
        );
        assert!(
            dispatch.app_state.is_none(),
            "non-UnlockedBusy source={source:?} must refuse to install a phantom Unlocked, \
             got {:?}",
            dispatch.app_state,
        );
    }
}

// ---------------------------------------------------------------------------
// apply_add_dispatch_inplace — `AppModel::update` mut-state wrapper
// ---------------------------------------------------------------------------
//
// Symmetric partner of `apply_rename_dispatch_inplace` for the add
// path. `compose_add_dispatch(&AppState, &AddWorkerEffect) ->
// AddDispatch` bundles the three worker-completion decisions; the
// wrapper here lets `AppMsg::AddWorkerCompleted` install the new
// `dispatch.app_state` against the cached `AppState` in place,
// mirroring `apply_submit_add_inplace`'s contract for the entry
// transition. The remaining `dialog_msg` / `drop_dialog` projections
// drive widget-side work in the handler and are not the wrapper's
// concern.

#[test]
fn apply_add_dispatch_inplace_success_rolls_back_to_unlocked_and_returns_true() {
    // Worker reported `Ok(())`: `compose_add_dispatch` carries
    // `Some(Unlocked(path))` in `app_state`. The wrapper installs the
    // rollback against the cached `UnlockedBusy` state and returns
    // `true` so `AppModel::update` can release the busy gate and drop
    // the `AddAccountComponent`.
    use paladin_gtk::add_account::AddWorkerEffect;
    use paladin_gtk::app::state::{apply_add_dispatch_inplace, compose_add_dispatch};

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let effect = AddWorkerEffect::Success {
        account_id: AccountId::new(),
    };
    let dispatch = compose_add_dispatch(&busy, &effect);
    let mut state = busy.clone();
    let transitioned = apply_add_dispatch_inplace(&mut state, &dispatch);
    assert!(
        transitioned,
        "apply_add_dispatch_inplace must return true on the Success rollback",
    );
    assert!(
        matches!(state, AppState::Unlocked { .. }),
        "Success rollback target must be Unlocked, got {state:?}",
    );
    assert_path_eq(&state, &path);
}

#[test]
fn apply_add_dispatch_inplace_failure_rolls_back_to_unlocked_and_returns_true() {
    // Worker reported a Failure: the add worker always rolls the busy
    // gate back to `Unlocked` regardless of typed effect because
    // `Vault::mutate_and_save` is authoritative for rollback /
    // durability-unconfirmed semantics. The wrapper installs the
    // rollback and returns `true`; widget-side work (the inline
    // message and the still-mounted dialog) is driven by the
    // remaining dispatch fields.
    use paladin_gtk::add_account::{classify_add_post_effect_error, AddWorkerEffect};
    use paladin_gtk::app::state::{apply_add_dispatch_inplace, compose_add_dispatch};

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let effect = AddWorkerEffect::Failure(classify_add_post_effect_error(&err));
    let dispatch = compose_add_dispatch(&busy, &effect);
    let mut state = busy.clone();
    let transitioned = apply_add_dispatch_inplace(&mut state, &dispatch);
    assert!(
        transitioned,
        "apply_add_dispatch_inplace must return true on the Failure rollback",
    );
    assert!(
        matches!(state, AppState::Unlocked { .. }),
        "Failure rollback target must be Unlocked, got {state:?}",
    );
    assert_path_eq(&state, &path);
}

#[test]
fn apply_add_dispatch_inplace_failure_keep_with_warning_rolls_back_to_unlocked_and_returns_true() {
    // The `save_durability_unconfirmed` branch also rolls
    // `UnlockedBusy → Unlocked`; the durability warning is forwarded
    // via `dispatch.dialog_msg` and not the wrapper's concern.
    use paladin_gtk::add_account::{classify_add_post_effect_error, AddWorkerEffect};
    use paladin_gtk::app::state::{apply_add_dispatch_inplace, compose_add_dispatch};

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = PaladinError::SaveDurabilityUnconfirmed;
    let effect = AddWorkerEffect::Failure(classify_add_post_effect_error(&err));
    let dispatch = compose_add_dispatch(&busy, &effect);
    let mut state = busy.clone();
    let transitioned = apply_add_dispatch_inplace(&mut state, &dispatch);
    assert!(
        transitioned,
        "KeepWithWarning rollback must transition UnlockedBusy → Unlocked",
    );
    assert!(matches!(state, AppState::Unlocked { .. }));
    assert_path_eq(&state, &path);
}

#[test]
fn apply_add_dispatch_inplace_from_non_unlocked_busy_leaves_state_unchanged_and_returns_false() {
    // Defensive: when the worker outcome arrives but the cached state
    // is not `UnlockedBusy` (a stray dispatch from any other source),
    // `compose_add_dispatch` reports `app_state = None` to refuse a
    // phantom `Unlocked` transition. The wrapper must leave the cached
    // state untouched byte-for-byte and return `false` so
    // `AppModel::update` does not clobber an idle state with a phantom
    // rollback.
    use paladin_gtk::add_account::{classify_add_post_effect_error, AddWorkerEffect};
    use paladin_gtk::app::state::{apply_add_dispatch_inplace, compose_add_dispatch};

    let path = vault_path();
    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let effect = AddWorkerEffect::Failure(classify_add_post_effect_error(&err));
    let invalid_sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
    ];
    for source in invalid_sources {
        let dispatch = compose_add_dispatch(&source, &effect);
        assert!(
            dispatch.app_state.is_none(),
            "fixture invariant: non-UnlockedBusy source must carry app_state=None",
        );
        let original_discriminant = std::mem::discriminant::<AppState>(&source);
        let original_path = source.path().map(Path::to_path_buf);
        let mut state = source.clone();
        let transitioned = apply_add_dispatch_inplace(&mut state, &dispatch);
        assert!(
            !transitioned,
            "apply_add_dispatch_inplace must return false when dispatch.app_state is None \
             for source={source:?}",
        );
        assert_eq!(
            std::mem::discriminant::<AppState>(&state),
            original_discriminant,
            "wrapper must leave variant unchanged when dispatch.app_state is None \
             for source={source:?}",
        );
        assert_eq!(
            state.path().map(Path::to_path_buf),
            original_path,
            "wrapper must leave path unchanged when dispatch.app_state is None \
             for source={source:?}",
        );
    }
}

// ---------------------------------------------------------------------------
// Add pipeline — full composition order `AppModel::update` walks for
// `AppMsg::AddWorkerCompleted`. Pins the exact sequence
// `compose_add_worker_input` → `apply_submit_add_inplace` →
// `run_add_worker` → `apply_add_vault_install_inplace` →
// `compose_add_dispatch` → `apply_add_dispatch_inplace`.
//
// Symmetric partner of `rename_pipeline_success_*` /
// `rename_pipeline_failure_*` for the add path. The individual
// projections are exhaustively tested above; these pipeline tests
// guard against composition-order regressions in `AppModel::update`.
// ---------------------------------------------------------------------------

#[test]
fn add_pipeline_success_returns_to_unlocked_with_new_account_and_drops_dialog() {
    // Happy path: the manual sub-path of `AddAccountComponent`
    // submits a validated `Account`; `AppModel::update` composes
    // the worker input over `Unlocked`, transitions to
    // `UnlockedBusy`, runs the worker (which commits the account
    // through `Vault::mutate_and_save`), reinstalls the post-save
    // pair, and dispatches over `UnlockedBusy + Success` to roll
    // back to `Unlocked` while dropping the dialog and forwarding
    // no inline message.
    use paladin_gtk::add_account::{run_add_worker, AddWorkerCompletion, AddWorkerEffect};
    use paladin_gtk::app::state::{
        apply_add_dispatch_inplace, apply_add_vault_install_inplace, compose_add_dispatch,
    };

    let (_tempdir, path, vault, store) = fresh_plaintext_pair();
    let account = fresh_add_account();
    let expected_id = account.id();
    let expected_label = account.label().to_string();

    // 1. Compose worker input from `Unlocked` over the live pair.
    let mut state = AppState::Unlocked { path: path.clone() };
    let mut vault_slot: Option<(Vault, Store)> = Some((vault, store));
    let worker_input = compose_add_worker_input(
        &state,
        vault_slot.take().expect("vault slot is filled"),
        account,
    )
    .expect("compose returns Ok when state is Unlocked");

    // 2. Busy-gate transition.
    let transitioned = apply_submit_add_inplace(&mut state);
    assert!(
        transitioned,
        "apply_submit_add_inplace must return true on Unlocked source"
    );
    assert!(
        matches!(state, AppState::UnlockedBusy { .. }),
        "state must be UnlockedBusy after apply_submit_add_inplace"
    );

    // 3. Worker body.
    let completion = run_add_worker(worker_input);
    let AddWorkerCompletion {
        effect,
        vault,
        store,
    } = completion;
    match &effect {
        AddWorkerEffect::Success { account_id } => {
            assert_eq!(
                *account_id, expected_id,
                "Success carries the validated-time id"
            );
        }
        other @ AddWorkerEffect::Failure(_) => {
            panic!("expected Success for a valid manual add, got {other:?}")
        }
    }

    // 4. Reinstall pair into the live slot.
    apply_add_vault_install_inplace(&mut vault_slot, (vault, store));
    let (installed_vault, _) = vault_slot.as_ref().expect("pair reinstalled");
    let added = installed_vault
        .accounts()
        .iter()
        .find(|a| a.id() == expected_id)
        .expect("added account survives mutate_and_save");
    assert_eq!(
        added.label(),
        expected_label,
        "vault must reflect the added account",
    );

    // 5. Dispatch over UnlockedBusy + Success.
    let dispatch = compose_add_dispatch(&state, &effect);
    assert!(dispatch.drop_dialog, "drop_dialog == true on Success");
    assert!(
        dispatch.dialog_msg.is_none(),
        "dialog_msg == None on Success (dropped dialog gets no message)",
    );
    let dispatched = apply_add_dispatch_inplace(&mut state, &dispatch);
    assert!(
        dispatched,
        "apply_add_dispatch_inplace must return true on UnlockedBusy source"
    );
    assert!(
        matches!(state, AppState::Unlocked { path: ref p } if *p == path),
        "state must be Unlocked at path after Success dispatch",
    );
}

#[test]
fn add_pipeline_failure_keeps_pair_installed_and_returns_to_unlocked() {
    // Failure path: simulate a `save_not_committed` outcome (the
    // worker returns the pre-commit `(Vault, Store)` snapshot
    // because `mutate_and_save` rolled back). The dispatch must
    // still roll the busy-gate back to `Unlocked`, must NOT drop
    // the dialog, and must forward a
    // `WorkerFailed(AddPostEffectOutcome::Inline(_))` to the live
    // `AddAccountComponent` so the inline error renders.
    //
    // `Vault::add` is infallible so a real save failure cannot be
    // forced from a happy-path fixture without mucking with disk
    // permissions; the synthetic outcome exercises the same
    // composition order the success test pins while the worker's
    // typed-failure path is independently covered by the
    // `apply_add_vault_install_inplace_consumes_run_add_worker_completion_pair`
    // / `compose_add_dispatch_failure_*` tests above.
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddAccountMsg, AddPostEffectOutcome, AddWorkerCompletion,
        AddWorkerEffect,
    };
    use paladin_gtk::app::state::{
        apply_add_dispatch_inplace, apply_add_vault_install_inplace, compose_add_dispatch,
    };

    let (_tempdir, path, vault, store) = fresh_plaintext_pair();

    let mut state = AppState::Unlocked { path: path.clone() };
    let mut vault_slot: Option<(Vault, Store)> = Some((vault, store));
    let _worker_input = compose_add_worker_input(
        &state,
        vault_slot.take().expect("vault slot is filled"),
        fresh_add_account(),
    )
    .expect("compose returns Ok when state is Unlocked");

    apply_submit_add_inplace(&mut state);
    assert!(matches!(state, AppState::UnlockedBusy { .. }));

    // Synthesize a typed `save_not_committed` failure as if
    // `mutate_and_save` had rolled back. The worker hands the pair
    // back regardless of typed outcome, so the test reuses a fresh
    // plaintext pair to stand in for the rolled-back snapshot.
    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let outcome = classify_add_post_effect_error(&err);
    assert!(matches!(outcome, AddPostEffectOutcome::Inline(_)));
    let (_tempdir2, _path2, vault, store) = fresh_plaintext_pair();
    let completion = AddWorkerCompletion {
        effect: AddWorkerEffect::Failure(outcome),
        vault,
        store,
    };
    let AddWorkerCompletion {
        effect,
        vault,
        store,
    } = completion;

    apply_add_vault_install_inplace(&mut vault_slot, (vault, store));
    assert!(
        vault_slot.is_some(),
        "pair must be reinstalled even on failure"
    );

    let dispatch = compose_add_dispatch(&state, &effect);
    assert!(!dispatch.drop_dialog, "drop_dialog == false on Failure");
    match dispatch.dialog_msg.as_ref() {
        Some(AddAccountMsg::WorkerFailed(AddPostEffectOutcome::Inline(_))) => {}
        other => panic!("dialog_msg must carry WorkerFailed(Inline) on Failure, got {other:?}"),
    }
    let dispatched = apply_add_dispatch_inplace(&mut state, &dispatch);
    assert!(
        dispatched,
        "apply_add_dispatch_inplace must transition on UnlockedBusy source"
    );
    assert!(
        matches!(state, AppState::Unlocked { path: ref p } if *p == path),
        "state must roll back to Unlocked on Failure (busy gate always releases)",
    );
}

// ---------------------------------------------------------------------------
// apply_qr_dispatch_inplace — `AppModel::update` mut-state wrapper for QR
// ---------------------------------------------------------------------------
//
// Symmetric partner of `apply_add_dispatch_inplace` for the clipboard-QR
// sub-path. `compose_qr_dispatch(&AppState, &QrWorkerEffect) -> QrDispatch`
// bundles the four worker-completion decisions (`app_state`, `dialog_msg`,
// `drop_dialog`, `refresh_list`); the wrapper here lets
// `AppMsg::QrWorkerCompleted` install the new `dispatch.app_state` against
// the cached `AppState` in place, mirroring `apply_add_dispatch_inplace`'s
// contract for the busy-gate rollback. The remaining `dialog_msg` /
// `drop_dialog` / `refresh_list` projections drive widget-side work in the
// handler and are not the wrapper's concern.

#[test]
fn apply_qr_dispatch_inplace_success_rolls_back_to_unlocked_and_returns_true() {
    // Worker reported `Ok(report)`: `compose_qr_dispatch` carries
    // `Some(Unlocked(path))` in `app_state` (the QR worker always
    // releases the busy gate). The wrapper installs the rollback
    // against the cached `UnlockedBusy` state and returns `true` so
    // `AppModel::update` can release the busy gate while the dialog
    // stays mounted to render the post-merge counts panel.
    use paladin_core::ImportReport;
    use paladin_gtk::add_account::QrWorkerEffect;
    use paladin_gtk::app::state::{apply_qr_dispatch_inplace, compose_qr_dispatch};

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let effect = QrWorkerEffect::Success(ImportReport::default());
    let dispatch = compose_qr_dispatch(&busy, &effect);
    let mut state = busy.clone();
    let transitioned = apply_qr_dispatch_inplace(&mut state, &dispatch);
    assert!(
        transitioned,
        "apply_qr_dispatch_inplace must return true on the Success rollback",
    );
    assert!(
        matches!(state, AppState::Unlocked { .. }),
        "Success rollback target must be Unlocked, got {state:?}",
    );
    assert_path_eq(&state, &path);
}

#[test]
fn apply_qr_dispatch_inplace_failure_inline_rolls_back_to_unlocked_and_returns_true() {
    // Worker reported a typed `Inline` failure
    // (e.g. `save_not_committed`): the QR worker always rolls the
    // busy gate back to `Unlocked` because `Vault::mutate_and_save`
    // is authoritative for the rollback semantics. The wrapper
    // installs the rollback and returns `true`; widget-side work
    // (the inline error and the still-mounted dialog) is driven by
    // the remaining dispatch fields.
    use paladin_gtk::add_account::{classify_add_post_effect_error, QrWorkerEffect};
    use paladin_gtk::app::state::{apply_qr_dispatch_inplace, compose_qr_dispatch};

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let effect = QrWorkerEffect::Failure(classify_add_post_effect_error(&err));
    let dispatch = compose_qr_dispatch(&busy, &effect);
    let mut state = busy.clone();
    let transitioned = apply_qr_dispatch_inplace(&mut state, &dispatch);
    assert!(
        transitioned,
        "apply_qr_dispatch_inplace must return true on the Failure rollback",
    );
    assert!(
        matches!(state, AppState::Unlocked { .. }),
        "Failure rollback target must be Unlocked, got {state:?}",
    );
    assert_path_eq(&state, &path);
}

#[test]
fn apply_qr_dispatch_inplace_failure_keep_with_warning_rolls_back_to_unlocked_and_returns_true() {
    // The `save_durability_unconfirmed` branch also rolls
    // `UnlockedBusy → Unlocked`; the durability warning is forwarded
    // via `dispatch.dialog_msg` as `WorkerFailed(KeepWithWarning(_))`
    // and is not the wrapper's concern.
    use paladin_gtk::add_account::{classify_add_post_effect_error, QrWorkerEffect};
    use paladin_gtk::app::state::{apply_qr_dispatch_inplace, compose_qr_dispatch};

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = PaladinError::SaveDurabilityUnconfirmed;
    let effect = QrWorkerEffect::Failure(classify_add_post_effect_error(&err));
    let dispatch = compose_qr_dispatch(&busy, &effect);
    let mut state = busy.clone();
    let transitioned = apply_qr_dispatch_inplace(&mut state, &dispatch);
    assert!(
        transitioned,
        "KeepWithWarning rollback must transition UnlockedBusy → Unlocked",
    );
    assert!(matches!(state, AppState::Unlocked { .. }));
    assert_path_eq(&state, &path);
}

#[test]
fn apply_qr_dispatch_inplace_from_non_unlocked_busy_leaves_state_unchanged_and_returns_false() {
    // Defensive: when the worker outcome arrives but the cached state
    // is not `UnlockedBusy` (a stray dispatch from any other source),
    // `compose_qr_dispatch` reports `app_state = None` to refuse a
    // phantom `Unlocked` transition. The wrapper must leave the
    // cached state untouched byte-for-byte and return `false` so
    // `AppModel::update` does not clobber an idle state with a
    // phantom rollback.
    use paladin_core::ImportReport;
    use paladin_gtk::add_account::QrWorkerEffect;
    use paladin_gtk::app::state::{apply_qr_dispatch_inplace, compose_qr_dispatch};

    let path = vault_path();
    let effect = QrWorkerEffect::Success(ImportReport::default());
    let invalid_sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
    ];
    for source in invalid_sources {
        let dispatch = compose_qr_dispatch(&source, &effect);
        assert!(
            dispatch.app_state.is_none(),
            "fixture invariant: non-UnlockedBusy source must carry app_state=None",
        );
        let original_discriminant = std::mem::discriminant::<AppState>(&source);
        let original_path = source.path().map(Path::to_path_buf);
        let mut state = source.clone();
        let transitioned = apply_qr_dispatch_inplace(&mut state, &dispatch);
        assert!(
            !transitioned,
            "apply_qr_dispatch_inplace must return false when dispatch.app_state is None \
             for source={source:?}",
        );
        assert_eq!(
            std::mem::discriminant::<AppState>(&state),
            original_discriminant,
            "wrapper must leave variant unchanged when dispatch.app_state is None \
             for source={source:?}",
        );
        assert_eq!(
            state.path().map(Path::to_path_buf),
            original_path,
            "wrapper must leave path unchanged when dispatch.app_state is None \
             for source={source:?}",
        );
    }
}

// ---------------------------------------------------------------------------
// QR pipeline — full composition order `AppModel::update` walks for
// `AppMsg::QrWorkerCompleted`. Pins the exact sequence
// `compose_qr_worker_input` → `apply_submit_add_inplace` →
// `run_qr_worker` → `apply_add_vault_install_inplace` →
// `compose_qr_dispatch` → `apply_qr_dispatch_inplace`.
//
// Symmetric partner of `add_pipeline_success_*` /
// `add_pipeline_failure_*` for the QR sub-path. The individual
// projections are exhaustively tested above; these pipeline tests
// guard against composition-order regressions in `AppModel::update`.
//
// Per `IMPLEMENTATION_PLAN_04_GTK.md` §"`AddAccountComponent` QR
// clipboard image path" > L2765: "Insert the returned accounts
// through `Vault::import_accounts(accounts, ImportConflict::Skip,
// import_time)` inside `Vault::mutate_and_save`; report imported /
// skipped / warning counts inline (parity with §6)". The
// `apply_add_vault_install_inplace` reuse is intentional — the QR
// sub-path shares the add path's `(Vault, Store)` reinstallation
// because both workers return the post-effect pair regardless of
// typed outcome.
// ---------------------------------------------------------------------------

/// Build a single-account validated QR import batch for the QR
/// pipeline fixtures. Mirrors the manual-add path's
/// `fresh_add_account` but emits the `ValidatedAccount` shape the QR
/// worker consumes (one entry per decoded QR).
fn fresh_qr_batch() -> Vec<paladin_core::ValidatedAccount> {
    use paladin_core::{validate_manual, AccountInput, AccountKindInput, Algorithm, IconHintInput};
    use secrecy::SecretString;

    let input = AccountInput {
        label: "qr-imported".to_string(),
        issuer: Some("qr-issuer".to_string()),
        secret: SecretString::from("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Totp,
        period_secs: None,
        counter: None,
        icon_hint: IconHintInput::Default,
    };
    vec![validate_manual(input, SystemTime::UNIX_EPOCH)
        .expect("totp account input validates for QR pipeline fixture")]
}

#[test]
fn qr_pipeline_success_returns_to_unlocked_with_imported_account_and_keeps_dialog_mounted() {
    // Happy path: the clipboard-QR sub-path of `AddAccountComponent`
    // submits a decoded `Vec<ValidatedAccount>`; `AppModel::update`
    // composes the QR worker input over `Unlocked`, transitions to
    // `UnlockedBusy`, runs the worker (which merges the batch
    // through `Vault::mutate_and_save(|v| v.import_accounts(...))`
    // under `ImportConflict::Skip`), reinstalls the post-save pair,
    // and dispatches over `UnlockedBusy + Success` to roll back to
    // `Unlocked` while keeping the dialog mounted (to render the
    // counts panel) and forwarding `QrSuccess(summary)` so the
    // dialog can render `imported`/`skipped`/`warning` counts inline.
    use paladin_gtk::add_account::{
        run_qr_worker, AddAccountMsg, QrWorkerCompletion, QrWorkerEffect,
    };
    use paladin_gtk::app::state::{
        apply_add_vault_install_inplace, apply_qr_dispatch_inplace, compose_qr_dispatch,
    };
    use paladin_gtk::qr_clipboard::QrImportSummary;

    let (_tempdir, path, vault, store) = fresh_plaintext_pair();
    let batch = fresh_qr_batch();
    let expected_label = batch[0].account.label().to_string();

    // 1. Compose worker input from `Unlocked` over the live pair.
    let mut state = AppState::Unlocked { path: path.clone() };
    let mut vault_slot: Option<(Vault, Store)> = Some((vault, store));
    let worker_input = compose_qr_worker_input(
        &state,
        vault_slot.take().expect("vault slot is filled"),
        batch,
        SystemTime::UNIX_EPOCH,
    )
    .expect("compose returns Ok when state is Unlocked");

    // 2. Busy-gate transition (shared with the add path because both
    //    workers consume the live pair and `import_accounts` is just
    //    a different `mutate_and_save` closure body).
    let transitioned = apply_submit_add_inplace(&mut state);
    assert!(
        transitioned,
        "apply_submit_add_inplace must return true on Unlocked source for QR sub-path"
    );
    assert!(
        matches!(state, AppState::UnlockedBusy { .. }),
        "state must be UnlockedBusy after apply_submit_add_inplace"
    );

    // 3. Worker body — `Vault::mutate_and_save(|v|
    //    v.import_accounts(..., ImportConflict::Skip, import_time))`.
    let completion = run_qr_worker(worker_input);
    let QrWorkerCompletion {
        effect,
        vault,
        store,
    } = completion;
    let report = match &effect {
        QrWorkerEffect::Success(report) => {
            assert_eq!(report.imported, 1, "single fresh account → imported=1");
            assert_eq!(report.skipped, 0, "no duplicate → skipped=0");
            report.clone()
        }
        other @ QrWorkerEffect::Failure(_) => {
            panic!("expected Success for a valid QR batch, got {other:?}")
        }
    };

    // 4. Reinstall pair into the live slot (the QR sub-path reuses
    //    the add path's installer because both workers return the
    //    post-effect pair regardless of typed outcome).
    apply_add_vault_install_inplace(&mut vault_slot, (vault, store));
    let (installed_vault, _) = vault_slot.as_ref().expect("pair reinstalled");
    let summary = installed_vault
        .summaries()
        .find(|s| s.label == expected_label)
        .expect("imported account survives mutate_and_save");
    assert_eq!(summary.issuer.as_deref(), Some("qr-issuer"));

    // 5. Dispatch over UnlockedBusy + Success.
    let dispatch = compose_qr_dispatch(&state, &effect);
    assert!(
        !dispatch.drop_dialog,
        "drop_dialog == false on QR Success (dialog stays mounted for counts panel)",
    );
    assert!(
        dispatch.refresh_list,
        "refresh_list == true on QR Success so the new row appears in the list",
    );
    match dispatch.dialog_msg.as_ref() {
        Some(AddAccountMsg::QrSuccess(s)) => {
            let expected = QrImportSummary::from_report(&report);
            assert_eq!(
                *s, expected,
                "dialog_msg must carry QrSuccess(QrImportSummary::from_report(report))",
            );
        }
        other => panic!("dialog_msg must carry QrSuccess on Success, got {other:?}"),
    }
    let dispatched = apply_qr_dispatch_inplace(&mut state, &dispatch);
    assert!(
        dispatched,
        "apply_qr_dispatch_inplace must return true on UnlockedBusy source"
    );
    assert!(
        matches!(state, AppState::Unlocked { path: ref p } if *p == path),
        "state must be Unlocked at path after Success dispatch",
    );
}

#[test]
fn qr_pipeline_failure_keeps_pair_installed_and_returns_to_unlocked_with_inline_dialog_msg() {
    // Failure path: simulate a `save_not_committed` outcome (the
    // worker returns the pre-commit `(Vault, Store)` snapshot
    // because `mutate_and_save` rolled back). The dispatch must
    // still roll the busy-gate back to `Unlocked`, must NOT drop
    // the dialog (the QR sub-path always keeps the dialog mounted),
    // and must forward a
    // `WorkerFailed(AddPostEffectOutcome::Inline(_))` to the live
    // `AddAccountComponent` so the inline error renders.
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddAccountMsg, AddPostEffectOutcome, QrWorkerCompletion,
        QrWorkerEffect,
    };
    use paladin_gtk::app::state::{
        apply_add_vault_install_inplace, apply_qr_dispatch_inplace, compose_qr_dispatch,
    };

    let (_tempdir, path, vault, store) = fresh_plaintext_pair();

    let mut state = AppState::Unlocked { path: path.clone() };
    let mut vault_slot: Option<(Vault, Store)> = Some((vault, store));
    let _worker_input = compose_qr_worker_input(
        &state,
        vault_slot.take().expect("vault slot is filled"),
        fresh_qr_batch(),
        SystemTime::UNIX_EPOCH,
    )
    .expect("compose returns Ok when state is Unlocked");

    apply_submit_add_inplace(&mut state);
    assert!(matches!(state, AppState::UnlockedBusy { .. }));

    // Synthesize a typed `save_not_committed` failure as if
    // `mutate_and_save` had rolled back. The worker hands the pair
    // back regardless of typed outcome, so the test reuses a fresh
    // plaintext pair to stand in for the rolled-back snapshot.
    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let outcome = classify_add_post_effect_error(&err);
    assert!(matches!(outcome, AddPostEffectOutcome::Inline(_)));
    let (_tempdir2, _path2, vault, store) = fresh_plaintext_pair();
    let completion = QrWorkerCompletion {
        effect: QrWorkerEffect::Failure(outcome),
        vault,
        store,
    };
    let QrWorkerCompletion {
        effect,
        vault,
        store,
    } = completion;

    apply_add_vault_install_inplace(&mut vault_slot, (vault, store));
    assert!(
        vault_slot.is_some(),
        "pair must be reinstalled even on failure"
    );

    let dispatch = compose_qr_dispatch(&state, &effect);
    assert!(
        !dispatch.drop_dialog,
        "drop_dialog == false on QR Failure (dialog stays mounted for inline error)",
    );
    assert!(
        !dispatch.refresh_list,
        "refresh_list == false on Inline failure (vault rolled back so list already matches disk)",
    );
    match dispatch.dialog_msg.as_ref() {
        Some(AddAccountMsg::WorkerFailed(AddPostEffectOutcome::Inline(_))) => {}
        other => panic!("dialog_msg must carry WorkerFailed(Inline) on Failure, got {other:?}"),
    }
    let dispatched = apply_qr_dispatch_inplace(&mut state, &dispatch);
    assert!(
        dispatched,
        "apply_qr_dispatch_inplace must transition on UnlockedBusy source"
    );
    assert!(
        matches!(state, AppState::Unlocked { path: ref p } if *p == path),
        "state must roll back to Unlocked on Failure (busy gate always releases)",
    );
}

#[test]
fn qr_pipeline_failure_keep_with_warning_keeps_pair_installed_refreshes_list_and_keeps_dialog_mounted(
) {
    // Durability-unconfirmed path: simulate a `save_durability_unconfirmed`
    // outcome from `Vault::mutate_and_save`. The merged accounts already
    // live in memory (matching the on-disk primary that committed past the
    // rename point), so the dispatch must:
    //
    // * Release the busy gate back to `Unlocked` so the row factory can
    //   re-project the live list.
    // * Forward `WorkerFailed(AddPostEffectOutcome::KeepWithWarning(_))`
    //   to the still-mounted `AddAccountComponent` so the durability
    //   warning renders via `post_effect_warning_label` against the
    //   dialog body where the counts panel would have been on Success.
    // * Set `refresh_list == true` so the visible row set picks up the
    //   newly merged accounts (the spec's "keeping the imported accounts
    //   visible" rule).
    // * Keep `drop_dialog == false` so the user sees the warning before
    //   dismissing.
    //
    // Mirror of `qr_pipeline_failure_keeps_pair_installed_and_returns_to_unlocked_with_inline_dialog_msg`
    // for the `KeepWithWarning` branch. Per `IMPLEMENTATION_PLAN_04_GTK.md`
    // §"`AddAccountComponent` QR clipboard image path" > "Handle
    // `save_durability_unconfirmed` by keeping the imported accounts visible
    // and surfacing the warning on the counts panel".
    use paladin_gtk::add_account::{
        classify_add_post_effect_error, AddAccountMsg, AddPostEffectOutcome, QrWorkerCompletion,
        QrWorkerEffect,
    };
    use paladin_gtk::app::state::{
        apply_add_vault_install_inplace, apply_qr_dispatch_inplace, compose_qr_dispatch,
    };

    let (_tempdir, path, vault, store) = fresh_plaintext_pair();

    let mut state = AppState::Unlocked { path: path.clone() };
    let mut vault_slot: Option<(Vault, Store)> = Some((vault, store));
    let _worker_input = compose_qr_worker_input(
        &state,
        vault_slot.take().expect("vault slot is filled"),
        fresh_qr_batch(),
        SystemTime::UNIX_EPOCH,
    )
    .expect("compose returns Ok when state is Unlocked");

    apply_submit_add_inplace(&mut state);
    assert!(matches!(state, AppState::UnlockedBusy { .. }));

    // Synthesize a typed `save_durability_unconfirmed` failure as if
    // `mutate_and_save` had committed past the rename point but the
    // parent fsync was not confirmed. The worker hands the pair back
    // (post-commit vault state) regardless of the typed outcome, so
    // the test reuses a fresh plaintext pair to stand in.
    let outcome = classify_add_post_effect_error(&PaladinError::SaveDurabilityUnconfirmed);
    assert!(matches!(outcome, AddPostEffectOutcome::KeepWithWarning(_)));
    let (_tempdir2, _path2, vault, store) = fresh_plaintext_pair();
    let completion = QrWorkerCompletion {
        effect: QrWorkerEffect::Failure(outcome),
        vault,
        store,
    };
    let QrWorkerCompletion {
        effect,
        vault,
        store,
    } = completion;

    apply_add_vault_install_inplace(&mut vault_slot, (vault, store));
    assert!(
        vault_slot.is_some(),
        "pair must be reinstalled even on durability-unconfirmed failure",
    );

    let dispatch = compose_qr_dispatch(&state, &effect);
    assert!(
        !dispatch.drop_dialog,
        "drop_dialog == false on KeepWithWarning (dialog stays mounted so warning renders)",
    );
    assert!(
        dispatch.refresh_list,
        "refresh_list == true on KeepWithWarning (merged accounts live on disk; list must surface them)",
    );
    match dispatch.dialog_msg.as_ref() {
        Some(AddAccountMsg::WorkerFailed(AddPostEffectOutcome::KeepWithWarning(_))) => {}
        other => panic!(
            "dialog_msg must carry WorkerFailed(KeepWithWarning) on durability-unconfirmed, got {other:?}",
        ),
    }
    let dispatched = apply_qr_dispatch_inplace(&mut state, &dispatch);
    assert!(
        dispatched,
        "apply_qr_dispatch_inplace must transition on UnlockedBusy source",
    );
    assert!(
        matches!(state, AppState::Unlocked { path: ref p } if *p == path),
        "state must roll back to Unlocked on KeepWithWarning (busy gate always releases)",
    );
}

// ---------------------------------------------------------------------------
// Import dispatch — entry-side bundling
// (submit_import_app_state / apply_submit_import_inplace /
// compose_import_worker_input). Symmetric partners of the rename /
// remove / add entry-side trio. The composer stays shape-only —
// `AppState` discriminant + carried-path cloning — so the tests
// exercise the routing rules without spinning up GTK / libadwaita.
// ---------------------------------------------------------------------------

#[test]
fn submit_import_app_state_from_unlocked_returns_unlocked_busy_preserving_path() {
    use paladin_gtk::app::state::submit_import_app_state;
    let path = vault_path();
    let unlocked = AppState::Unlocked { path: path.clone() };
    let next =
        submit_import_app_state(&unlocked).expect("Unlocked enters UnlockedBusy on Import submit");
    assert!(matches!(next, AppState::UnlockedBusy { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn submit_import_app_state_from_non_unlocked_returns_none() {
    use paladin_gtk::app::state::submit_import_app_state;
    let path = vault_path();
    assert!(submit_import_app_state(&AppState::Missing { path: path.clone() }).is_none());
    assert!(submit_import_app_state(&AppState::Locked { path: path.clone() }).is_none());
    assert!(submit_import_app_state(&AppState::UnlockedBusy { path: path.clone() }).is_none());
    let startup = decide_state_from_inspect(&path, Err(invalid_header_err()))
        .expect("inspect Err yields StartupError state");
    assert!(submit_import_app_state(&startup).is_none());
}

#[test]
fn apply_submit_import_inplace_from_unlocked_mutates_to_unlocked_busy_and_returns_true() {
    use paladin_gtk::app::state::apply_submit_import_inplace;
    let path = vault_path();
    let mut state = AppState::Unlocked { path: path.clone() };
    let mutated = apply_submit_import_inplace(&mut state);
    assert!(mutated);
    assert!(matches!(state, AppState::UnlockedBusy { .. }));
    assert_path_eq(&state, &path);
}

#[test]
fn apply_submit_import_inplace_from_non_unlocked_leaves_state_unchanged_and_returns_false() {
    use paladin_gtk::app::state::apply_submit_import_inplace;
    let path = vault_path();
    let sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::UnlockedBusy { path: path.clone() },
    ];
    for source in sources {
        let mut state = source.clone();
        let mutated = apply_submit_import_inplace(&mut state);
        assert!(
            !mutated,
            "non-Unlocked source must not transition: {source:?}"
        );
        // The state stays byte-for-byte the same except for the
        // shadow `Debug` form — compare the discriminant via
        // `mem::discriminant`.
        assert_eq!(
            std::mem::discriminant(&state),
            std::mem::discriminant(&source),
        );
    }
}

#[test]
fn compose_import_worker_input_from_unlocked_bundles_pair_payload_and_import_time() {
    use paladin_core::ImportFormat;
    use paladin_gtk::app::state::compose_import_worker_input;
    use paladin_gtk::import_dialog::{
        build_import_options, ImportSubmitPayload, ImportWorkerInput,
    };

    let (_tempdir, _path, vault, store) = fresh_plaintext_pair();
    let path = vault_path();
    let unlocked = AppState::Unlocked { path: path.clone() };

    let payload = ImportSubmitPayload {
        source_path: PathBuf::from("/tmp/some-source.json"),
        options: build_import_options(paladin_gtk::import_dialog::FormatChoice::Otpauth, None),
        conflict: paladin_core::ImportConflict::Skip,
    };
    let import_time = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(54_321);

    let bundled: ImportWorkerInput =
        compose_import_worker_input(&unlocked, (vault, store), payload, import_time)
            .expect("Unlocked bundles the worker input");
    assert_eq!(bundled.source_path, PathBuf::from("/tmp/some-source.json"));
    assert_eq!(bundled.options.format, Some(ImportFormat::Otpauth));
    assert_eq!(bundled.conflict, paladin_core::ImportConflict::Skip);
    assert_eq!(
        bundled.import_time, import_time,
        "composer must preserve the dispatch-site import_time so a long worker queue \
         still uses the same timestamp the user submitted at",
    );
}

#[test]
fn compose_import_worker_input_from_non_unlocked_returns_pair_back() {
    use paladin_gtk::app::state::compose_import_worker_input;
    use paladin_gtk::import_dialog::{build_import_options, ImportSubmitPayload};

    let path = vault_path();
    let sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::UnlockedBusy { path: path.clone() },
    ];
    for source in &sources {
        let (_tempdir, _path, vault, store) = fresh_plaintext_pair();
        let payload = ImportSubmitPayload {
            source_path: PathBuf::from("/tmp/source.json"),
            options: build_import_options(
                paladin_gtk::import_dialog::FormatChoice::AutoDetect,
                None,
            ),
            conflict: paladin_core::ImportConflict::Skip,
        };
        let import_time = SystemTime::UNIX_EPOCH;
        let result = compose_import_worker_input(source, (vault, store), payload, import_time);
        assert!(
            result.is_err(),
            "non-Unlocked source must return the pair back: {source:?}",
        );
    }
}

// ---------------------------------------------------------------------------
// Import dispatch — completion-side trio
// (import_final_app_state / should_drop_import_dialog_after /
// import_dialog_msg_after / should_refresh_list_after_import) plus
// the bundled ImportDispatch / compose_import_dispatch /
// apply_import_dispatch_inplace / apply_import_vault_install_inplace
// wrapping pair. The dialog stays mounted on every outcome (per
// IMPLEMENTATION_PLAN_04_GTK.md §"Component tree" > ImportDialog).
// ---------------------------------------------------------------------------

fn import_report_success(imported: usize) -> paladin_core::ImportReport {
    paladin_core::ImportReport {
        imported,
        ..paladin_core::ImportReport::default()
    }
}

#[test]
fn import_final_app_state_success_rolls_back_to_unlocked_preserving_path() {
    use paladin_gtk::app::state::import_final_app_state;
    use paladin_gtk::import_dialog::classify_merge_result;
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let outcome = classify_merge_result(Ok(import_report_success(3)));
    let next = import_final_app_state(&busy, &outcome)
        .expect("Success rolls UnlockedBusy back to Unlocked");
    assert!(matches!(next, AppState::Unlocked { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn import_final_app_state_failure_rolls_back_to_unlocked_for_every_outcome() {
    use paladin_gtk::app::state::import_final_app_state;
    use paladin_gtk::import_dialog::classify_merge_result;
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let outcomes = [
        classify_merge_result(Err(PaladinError::SaveNotCommitted {
            committed: false,
            backup_path: None,
        })),
        classify_merge_result(Err(PaladinError::SaveDurabilityUnconfirmed)),
        classify_merge_result(Err(PaladinError::NoEntriesToImport)),
    ];
    for outcome in &outcomes {
        let next = import_final_app_state(&busy, outcome)
            .expect("every outcome rolls UnlockedBusy back to Unlocked");
        assert!(matches!(next, AppState::Unlocked { .. }));
        assert_path_eq(&next, &path);
    }
}

#[test]
fn import_final_app_state_from_non_unlocked_busy_returns_none() {
    use paladin_gtk::app::state::import_final_app_state;
    use paladin_gtk::import_dialog::classify_merge_result;
    let path = vault_path();
    let outcome = classify_merge_result(Ok(import_report_success(0)));
    let sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
    ];
    for source in &sources {
        assert!(
            import_final_app_state(source, &outcome).is_none(),
            "non-UnlockedBusy source must not install a phantom Unlocked: {source:?}",
        );
    }
}

#[test]
fn should_drop_import_dialog_after_is_always_false() {
    use paladin_gtk::app::state::should_drop_import_dialog_after;
    use paladin_gtk::import_dialog::classify_merge_result;
    let outcomes = [
        classify_merge_result(Ok(import_report_success(1))),
        classify_merge_result(Err(PaladinError::SaveNotCommitted {
            committed: false,
            backup_path: None,
        })),
        classify_merge_result(Err(PaladinError::SaveDurabilityUnconfirmed)),
        classify_merge_result(Err(PaladinError::NoEntriesToImport)),
        classify_merge_result(Err(PaladinError::InvalidHeader)),
    ];
    for outcome in &outcomes {
        assert!(
            !should_drop_import_dialog_after(outcome),
            "ImportDialog must stay mounted on every outcome (counts panel / inline error): {outcome:?}",
        );
    }
}

#[test]
fn import_dialog_msg_after_always_forwards_worker_completed() {
    use paladin_gtk::app::state::import_dialog_msg_after;
    use paladin_gtk::import_dialog::{classify_merge_result, ImportDialogMsg, MergeOutcome};
    let outcomes = [
        classify_merge_result(Ok(import_report_success(2))),
        classify_merge_result(Err(PaladinError::SaveNotCommitted {
            committed: false,
            backup_path: None,
        })),
        classify_merge_result(Err(PaladinError::SaveDurabilityUnconfirmed)),
        classify_merge_result(Err(PaladinError::NoEntriesToImport)),
    ];
    for outcome in &outcomes {
        let msg =
            import_dialog_msg_after(outcome).expect("every outcome forwards a WorkerCompleted msg");
        match (msg, outcome) {
            (ImportDialogMsg::WorkerCompleted(a), b) => {
                assert!(
                    matches!(
                        (&a, b),
                        (MergeOutcome::Success(_), MergeOutcome::Success(_))
                            | (MergeOutcome::NotCommitted(_), MergeOutcome::NotCommitted(_))
                            | (
                                MergeOutcome::DurabilityWarning(_),
                                MergeOutcome::DurabilityWarning(_),
                            )
                            | (MergeOutcome::Inline(_), MergeOutcome::Inline(_))
                    ),
                    "msg must carry the matching variant for outcome",
                );
            }
            (other, _) => panic!("dialog_msg must be WorkerCompleted, got {other:?}"),
        }
    }
}

#[test]
fn should_refresh_list_after_import_partitions_on_committed_outcomes() {
    use paladin_gtk::app::state::should_refresh_list_after_import;
    use paladin_gtk::import_dialog::classify_merge_result;
    let refresh = [
        classify_merge_result(Ok(import_report_success(0))),
        classify_merge_result(Ok(import_report_success(7))),
        classify_merge_result(Err(PaladinError::SaveDurabilityUnconfirmed)),
    ];
    let skip = [
        classify_merge_result(Err(PaladinError::SaveNotCommitted {
            committed: false,
            backup_path: None,
        })),
        classify_merge_result(Err(PaladinError::SaveNotCommitted {
            committed: true,
            backup_path: None,
        })),
        classify_merge_result(Err(PaladinError::NoEntriesToImport)),
        classify_merge_result(Err(PaladinError::InvalidHeader)),
        classify_merge_result(Err(PaladinError::DecryptFailed)),
    ];
    for outcome in &refresh {
        assert!(
            should_refresh_list_after_import(outcome),
            "refresh partition expects true: {outcome:?}",
        );
    }
    for outcome in &skip {
        assert!(
            !should_refresh_list_after_import(outcome),
            "skip partition expects false: {outcome:?}",
        );
    }
}

#[test]
fn compose_import_dispatch_success_bundles_dialog_msg_and_unlocked_rollback() {
    use paladin_gtk::app::state::compose_import_dispatch;
    use paladin_gtk::import_dialog::{classify_merge_result, ImportDialogMsg, MergeOutcome};
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let outcome = classify_merge_result(Ok(import_report_success(3)));
    let dispatch = compose_import_dispatch(&busy, &outcome);
    assert!(
        !dispatch.drop_dialog,
        "ImportDialog stays mounted on Success so the counts panel renders",
    );
    assert!(
        dispatch.refresh_list,
        "Success refreshes the list so merged accounts appear",
    );
    let msg = dispatch
        .dialog_msg
        .as_ref()
        .expect("forwards WorkerCompleted");
    assert!(matches!(
        msg,
        ImportDialogMsg::WorkerCompleted(MergeOutcome::Success(_)),
    ));
    let next = dispatch.app_state.expect("Success rolls back to Unlocked");
    assert!(matches!(next, AppState::Unlocked { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn compose_import_dispatch_failure_keeps_dialog_with_msg_and_unlocked_rollback() {
    use paladin_gtk::app::state::compose_import_dispatch;
    use paladin_gtk::import_dialog::{classify_merge_result, ImportDialogMsg, MergeOutcome};
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let outcome = classify_merge_result(Err(PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    }));
    let dispatch = compose_import_dispatch(&busy, &outcome);
    assert!(!dispatch.drop_dialog);
    assert!(
        !dispatch.refresh_list,
        "NotCommitted leaves vault state unchanged so no list refresh is needed",
    );
    let msg = dispatch
        .dialog_msg
        .as_ref()
        .expect("forwards WorkerCompleted");
    assert!(matches!(
        msg,
        ImportDialogMsg::WorkerCompleted(MergeOutcome::NotCommitted(_)),
    ));
    let next = dispatch
        .app_state
        .expect("Failure still rolls UnlockedBusy back to Unlocked");
    assert!(matches!(next, AppState::Unlocked { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn compose_import_dispatch_durability_warning_keeps_dialog_and_refreshes_list() {
    use paladin_gtk::app::state::compose_import_dispatch;
    use paladin_gtk::import_dialog::{classify_merge_result, ImportDialogMsg, MergeOutcome};
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let outcome = classify_merge_result(Err(PaladinError::SaveDurabilityUnconfirmed));
    let dispatch = compose_import_dispatch(&busy, &outcome);
    assert!(!dispatch.drop_dialog);
    assert!(
        dispatch.refresh_list,
        "DurabilityWarning commits merged accounts in memory so the list must surface them",
    );
    let msg = dispatch
        .dialog_msg
        .as_ref()
        .expect("forwards WorkerCompleted");
    assert!(matches!(
        msg,
        ImportDialogMsg::WorkerCompleted(MergeOutcome::DurabilityWarning(_)),
    ));
}

#[test]
fn compose_import_dispatch_from_non_unlocked_busy_returns_no_app_state() {
    use paladin_gtk::app::state::compose_import_dispatch;
    use paladin_gtk::import_dialog::classify_merge_result;
    let path = vault_path();
    let outcome = classify_merge_result(Ok(import_report_success(1)));
    let sources = [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
    ];
    for source in &sources {
        let dispatch = compose_import_dispatch(source, &outcome);
        assert!(dispatch.app_state.is_none(), "source={source:?}");
        assert!(
            !dispatch.drop_dialog,
            "drop_dialog stays false even for stray dispatches",
        );
        assert!(
            dispatch.dialog_msg.is_some(),
            "dialog_msg still mirrors import_dialog_msg_after",
        );
    }
}

#[test]
fn apply_import_dispatch_inplace_success_rolls_back_to_unlocked_and_returns_true() {
    use paladin_gtk::app::state::{apply_import_dispatch_inplace, compose_import_dispatch};
    use paladin_gtk::import_dialog::classify_merge_result;
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let outcome = classify_merge_result(Ok(import_report_success(2)));
    let dispatch = compose_import_dispatch(&busy, &outcome);
    let mut state = busy.clone();
    let mutated = apply_import_dispatch_inplace(&mut state, &dispatch);
    assert!(mutated);
    assert!(matches!(state, AppState::Unlocked { .. }));
    assert_path_eq(&state, &path);
}

#[test]
fn apply_import_dispatch_inplace_from_non_unlocked_busy_leaves_state_unchanged_and_returns_false() {
    use paladin_gtk::app::state::{apply_import_dispatch_inplace, compose_import_dispatch};
    use paladin_gtk::import_dialog::classify_merge_result;
    let path = vault_path();
    let mut state = AppState::Unlocked { path: path.clone() };
    let outcome = classify_merge_result(Ok(import_report_success(1)));
    let dispatch = compose_import_dispatch(&state, &outcome);
    let mutated = apply_import_dispatch_inplace(&mut state, &dispatch);
    assert!(!mutated);
    assert!(matches!(state, AppState::Unlocked { .. }));
}

#[test]
fn apply_import_vault_install_inplace_writes_pair_into_empty_slot() {
    use paladin_gtk::app::state::apply_import_vault_install_inplace;
    let (_tempdir, _path, vault, store) = fresh_plaintext_pair();
    let mut slot: Option<(Vault, Store)> = None;
    apply_import_vault_install_inplace(&mut slot, (vault, store));
    assert!(slot.is_some());
}

#[test]
fn apply_import_vault_install_inplace_replaces_existing_slot() {
    use paladin_gtk::app::state::apply_import_vault_install_inplace;
    let (_tempdir1, _path1, vault1, store1) = fresh_plaintext_pair();
    let (_tempdir2, _path2, vault2, store2) = fresh_plaintext_pair();
    let mut slot: Option<(Vault, Store)> = Some((vault1, store1));
    apply_import_vault_install_inplace(&mut slot, (vault2, store2));
    assert!(slot.is_some());
}

// ---------------------------------------------------------------------------
// submit_passphrase_app_state / apply_submit_passphrase_inplace —
// pre-worker `Unlocked → UnlockedBusy` busy-gate composer for the
// passphrase-transition path.
//
// Mirrors the `submit_remove_app_state` / `submit_rename_app_state`
// suite: the `Unlocked` source transitions to `UnlockedBusy`
// preserving the path; every other source is a defensive no-op.
// ---------------------------------------------------------------------------

#[test]
fn submit_passphrase_app_state_from_unlocked_returns_unlocked_busy_preserving_path() {
    use paladin_gtk::app::state::submit_passphrase_app_state;
    let path = vault_path();
    let unlocked = AppState::Unlocked { path: path.clone() };
    let next = submit_passphrase_app_state(&unlocked)
        .expect("Unlocked must transition to UnlockedBusy on passphrase submit");
    assert!(matches!(next, AppState::UnlockedBusy { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn submit_passphrase_app_state_from_non_unlocked_returns_none() {
    use paladin_gtk::app::state::submit_passphrase_app_state;
    let path = vault_path();
    assert!(submit_passphrase_app_state(&AppState::Missing { path: path.clone() }).is_none());
    assert!(submit_passphrase_app_state(&AppState::Locked { path: path.clone() }).is_none());
    assert!(submit_passphrase_app_state(&AppState::UnlockedBusy { path: path.clone() }).is_none());
    let startup = decide_state_from_inspect(&path, Err(invalid_header_err()))
        .expect("inspect Err yields StartupError state");
    assert!(submit_passphrase_app_state(&startup).is_none());
}

#[test]
fn apply_submit_passphrase_inplace_from_unlocked_mutates_to_unlocked_busy_and_returns_true() {
    use paladin_gtk::app::state::apply_submit_passphrase_inplace;
    let path = vault_path();
    let mut state = AppState::Unlocked { path: path.clone() };
    let mutated = apply_submit_passphrase_inplace(&mut state);
    assert!(mutated);
    assert!(matches!(state, AppState::UnlockedBusy { .. }));
    assert_path_eq(&state, &path);
}

#[test]
fn apply_submit_passphrase_inplace_from_non_unlocked_returns_false_and_keeps_state() {
    use paladin_gtk::app::state::apply_submit_passphrase_inplace;
    let path = vault_path();
    for variant in [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::UnlockedBusy { path: path.clone() },
    ] {
        let mut state = variant.clone();
        let mutated = apply_submit_passphrase_inplace(&mut state);
        assert!(!mutated);
        // Source byte-for-byte intact: the discriminant is preserved.
        match (&state, &variant) {
            (AppState::Missing { .. }, AppState::Missing { .. })
            | (AppState::Locked { .. }, AppState::Locked { .. })
            | (AppState::UnlockedBusy { .. }, AppState::UnlockedBusy { .. }) => {}
            other => panic!("source variant must be preserved, got {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// compose_passphrase_worker_input — bundles `(Vault, Store, SubmitPayload)`
// into a `PassphraseWorkerInput` for the `gio::spawn_blocking` worker.
// `Unlocked` returns `Ok(input)`; every other variant returns
// `Err(pair)` so the dispatch site can reinstall the live pair.
// ---------------------------------------------------------------------------

fn passphrase_remove_payload() -> paladin_gtk::passphrase_dialog::SubmitPayload {
    // `Remove` carries no secret payload — the simplest fixture for
    // the composer tests since it does not need a real
    // `EncryptionOptions`.
    paladin_gtk::passphrase_dialog::SubmitPayload::Remove
}

#[test]
fn compose_passphrase_worker_input_from_unlocked_bundles_pair_and_payload() {
    use paladin_gtk::app::state::compose_passphrase_worker_input;
    let (_tempdir, path, vault, store) = fresh_plaintext_pair();
    let unlocked = AppState::Unlocked { path: path.clone() };

    let input =
        compose_passphrase_worker_input(&unlocked, (vault, store), passphrase_remove_payload())
            .expect("Unlocked source must produce a PassphraseWorkerInput");

    // The worker payload arm matches the input we passed in.
    assert!(matches!(
        input.payload,
        paladin_gtk::passphrase_dialog::SubmitPayload::Remove
    ));
    // The bundled vault is the live one (zero accounts in this fixture).
    assert_eq!(input.vault.summaries().count(), 0);
}

#[test]
fn compose_passphrase_worker_input_from_non_unlocked_returns_pair_back() {
    use paladin_gtk::app::state::compose_passphrase_worker_input;
    for variant in ["missing", "locked", "unlocked_busy", "startup_error"] {
        let (_tempdir, path, vault, store) = fresh_plaintext_pair();
        let source = match variant {
            "missing" => AppState::Missing { path: path.clone() },
            "locked" => AppState::Locked { path: path.clone() },
            "unlocked_busy" => AppState::UnlockedBusy { path: path.clone() },
            "startup_error" => decide_state_from_inspect(&path, Err(invalid_header_err()))
                .expect("inspect Err yields StartupError state"),
            _ => unreachable!(),
        };
        let result =
            compose_passphrase_worker_input(&source, (vault, store), passphrase_remove_payload());
        assert!(
            result.is_err(),
            "non-Unlocked source must return Err(pair), variant={variant}",
        );
        let (returned_vault, _returned_store) = result.err().unwrap();
        assert_eq!(returned_vault.summaries().count(), 0);
    }
}

// ---------------------------------------------------------------------------
// compose_passphrase_dispatch — aggregates the four routing
// projections (app_state rollback, dialog_msg, drop_dialog,
// success_toast) from the typed `PassphraseWorkerEffect`.
// ---------------------------------------------------------------------------

#[test]
fn compose_passphrase_dispatch_success_drops_dialog_and_rolls_busy_back() {
    use paladin_gtk::app::state::compose_passphrase_dispatch;
    use paladin_gtk::passphrase_dialog::{PassphraseWorkerEffect, SubFlow};

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let effect = PassphraseWorkerEffect::Success {
        sub_flow: SubFlow::Set,
        new_is_encrypted: true,
    };

    let dispatch = compose_passphrase_dispatch(&busy, &effect);

    assert!(dispatch.drop_dialog, "success must drop the dialog");
    assert!(
        dispatch.dialog_msg.is_none(),
        "success must not forward an inline message",
    );
    assert!(
        matches!(dispatch.app_state, Some(AppState::Unlocked { .. })),
        "busy gate must roll back on success",
    );
    assert!(
        dispatch.success_toast.is_some(),
        "success must raise a confirmation toast",
    );
}

#[test]
fn compose_passphrase_dispatch_failure_keeps_dialog_with_worker_failed_msg() {
    use paladin_gtk::app::state::compose_passphrase_dispatch;
    use paladin_gtk::passphrase_dialog::{
        classify_passphrase_error, PassphraseDialogMsg, PassphraseWorkerEffect,
    };

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let err = paladin_core::PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let outcome = classify_passphrase_error(&err);
    let effect = PassphraseWorkerEffect::Failure(outcome);

    let dispatch = compose_passphrase_dispatch(&busy, &effect);

    assert!(
        !dispatch.drop_dialog,
        "failure must keep the dialog mounted",
    );
    assert!(
        matches!(
            dispatch.dialog_msg,
            Some(PassphraseDialogMsg::WorkerFailed(_))
        ),
        "failure must forward WorkerFailed to the dialog",
    );
    assert!(
        matches!(dispatch.app_state, Some(AppState::Unlocked { .. })),
        "busy gate must roll back even on failure",
    );
    assert!(
        dispatch.success_toast.is_none(),
        "failure must not raise a confirmation toast",
    );
}

#[test]
fn compose_passphrase_dispatch_from_non_unlocked_busy_returns_no_app_state() {
    use paladin_gtk::app::state::compose_passphrase_dispatch;
    use paladin_gtk::passphrase_dialog::{PassphraseWorkerEffect, SubFlow};

    let path = vault_path();
    let effect = PassphraseWorkerEffect::Success {
        sub_flow: SubFlow::Set,
        new_is_encrypted: true,
    };

    for source in [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
    ] {
        let dispatch = compose_passphrase_dispatch(&source, &effect);
        assert!(
            dispatch.app_state.is_none(),
            "non-UnlockedBusy source must not install a phantom Unlocked",
        );
    }
}

#[test]
fn apply_passphrase_dispatch_inplace_applies_unlocked_rollback() {
    use paladin_gtk::app::state::{apply_passphrase_dispatch_inplace, compose_passphrase_dispatch};
    use paladin_gtk::passphrase_dialog::{PassphraseWorkerEffect, SubFlow};

    let path = vault_path();
    let mut state = AppState::UnlockedBusy { path: path.clone() };
    let dispatch = compose_passphrase_dispatch(
        &state,
        &PassphraseWorkerEffect::Success {
            sub_flow: SubFlow::Set,
            new_is_encrypted: true,
        },
    );
    let mutated = apply_passphrase_dispatch_inplace(&mut state, &dispatch);
    assert!(mutated);
    assert!(matches!(state, AppState::Unlocked { .. }));
    assert_path_eq(&state, &path);
}

#[test]
fn apply_passphrase_dispatch_inplace_noop_when_app_state_is_none() {
    use paladin_gtk::app::state::{apply_passphrase_dispatch_inplace, compose_passphrase_dispatch};
    use paladin_gtk::passphrase_dialog::{PassphraseWorkerEffect, SubFlow};

    let path = vault_path();
    let mut state = AppState::Unlocked { path: path.clone() };
    let dispatch = compose_passphrase_dispatch(
        &state,
        &PassphraseWorkerEffect::Success {
            sub_flow: SubFlow::Set,
            new_is_encrypted: true,
        },
    );
    let mutated = apply_passphrase_dispatch_inplace(&mut state, &dispatch);
    assert!(!mutated);
    assert!(matches!(state, AppState::Unlocked { .. }));
}

#[test]
fn apply_passphrase_vault_install_inplace_writes_pair_into_empty_slot() {
    use paladin_gtk::app::state::apply_passphrase_vault_install_inplace;
    let (_tempdir, _path, vault, store) = fresh_plaintext_pair();
    let mut slot: Option<(Vault, Store)> = None;
    apply_passphrase_vault_install_inplace(&mut slot, (vault, store));
    assert!(slot.is_some());
}

#[test]
fn apply_passphrase_vault_install_inplace_replaces_existing_slot() {
    use paladin_gtk::app::state::apply_passphrase_vault_install_inplace;
    let (_tempdir1, _path1, vault1, store1) = fresh_plaintext_pair();
    let (_tempdir2, _path2, vault2, store2) = fresh_plaintext_pair();
    let mut slot: Option<(Vault, Store)> = Some((vault1, store1));
    apply_passphrase_vault_install_inplace(&mut slot, (vault2, store2));
    assert!(slot.is_some());
}

// ---------------------------------------------------------------------------
// passphrase_new_is_encrypted_after — visible vault-mode-flag projection
// for the typed `PassphraseWorkerEffect`.
//
// Per `IMPLEMENTATION_PLAN_04_GTK.md` §"PassphraseDialog full
// implementation" checklist line 3403: "On success, update the visible
// vault-mode flag before closing the dialog, post a status / toast
// confirmation, and re-ask `IdlePolicy::should_arm` so the auto-lock
// timer state tracks the new on-disk mode." The success projection
// carries the worker's post-transition `new_is_encrypted` so downstream
// consumers (menu sub-flow gating, auto-lock arming) do not need to
// round-trip through the live `Vault::is_encrypted()` getter again.
// ---------------------------------------------------------------------------

#[test]
fn passphrase_new_is_encrypted_after_success_set_returns_some_true() {
    use paladin_gtk::app::state::passphrase_new_is_encrypted_after;
    use paladin_gtk::passphrase_dialog::{PassphraseWorkerEffect, SubFlow};

    let effect = PassphraseWorkerEffect::Success {
        sub_flow: SubFlow::Set,
        new_is_encrypted: true,
    };
    assert_eq!(passphrase_new_is_encrypted_after(&effect), Some(true));
}

#[test]
fn passphrase_new_is_encrypted_after_success_remove_returns_some_false() {
    use paladin_gtk::app::state::passphrase_new_is_encrypted_after;
    use paladin_gtk::passphrase_dialog::{PassphraseWorkerEffect, SubFlow};

    let effect = PassphraseWorkerEffect::Success {
        sub_flow: SubFlow::Remove,
        new_is_encrypted: false,
    };
    assert_eq!(passphrase_new_is_encrypted_after(&effect), Some(false));
}

#[test]
fn passphrase_new_is_encrypted_after_success_change_preserves_encrypted_mode() {
    use paladin_gtk::app::state::passphrase_new_is_encrypted_after;
    use paladin_gtk::passphrase_dialog::{PassphraseWorkerEffect, SubFlow};

    // `Change` keeps the vault encrypted — the projection still
    // reports the post-transition mode so the caller does not have to
    // special-case it.
    let effect = PassphraseWorkerEffect::Success {
        sub_flow: SubFlow::Change,
        new_is_encrypted: true,
    };
    assert_eq!(passphrase_new_is_encrypted_after(&effect), Some(true));
}

#[test]
fn passphrase_new_is_encrypted_after_failure_returns_none() {
    use paladin_gtk::app::state::passphrase_new_is_encrypted_after;
    use paladin_gtk::passphrase_dialog::{classify_passphrase_error, PassphraseWorkerEffect};

    let err = paladin_core::PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let outcome = classify_passphrase_error(&err);
    let effect = PassphraseWorkerEffect::Failure(outcome);
    assert_eq!(
        passphrase_new_is_encrypted_after(&effect),
        None,
        "the dialog stays open on every failure branch — no mode flip to project",
    );
}

#[test]
fn compose_passphrase_dispatch_success_projects_new_is_encrypted_true() {
    use paladin_gtk::app::state::compose_passphrase_dispatch;
    use paladin_gtk::passphrase_dialog::{PassphraseWorkerEffect, SubFlow};

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path };
    let effect = PassphraseWorkerEffect::Success {
        sub_flow: SubFlow::Set,
        new_is_encrypted: true,
    };
    let dispatch = compose_passphrase_dispatch(&busy, &effect);
    assert_eq!(
        dispatch.new_is_encrypted,
        Some(true),
        "Set success must propagate the new encrypted-mode flag",
    );
}

#[test]
fn compose_passphrase_dispatch_success_projects_new_is_encrypted_false() {
    use paladin_gtk::app::state::compose_passphrase_dispatch;
    use paladin_gtk::passphrase_dialog::{PassphraseWorkerEffect, SubFlow};

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path };
    let effect = PassphraseWorkerEffect::Success {
        sub_flow: SubFlow::Remove,
        new_is_encrypted: false,
    };
    let dispatch = compose_passphrase_dispatch(&busy, &effect);
    assert_eq!(
        dispatch.new_is_encrypted,
        Some(false),
        "Remove success must propagate the new plaintext-mode flag",
    );
}

#[test]
fn compose_passphrase_dispatch_failure_projects_no_new_is_encrypted() {
    use paladin_gtk::app::state::compose_passphrase_dispatch;
    use paladin_gtk::passphrase_dialog::{classify_passphrase_error, PassphraseWorkerEffect};

    let path = vault_path();
    let busy = AppState::UnlockedBusy { path };
    let err = paladin_core::PaladinError::SaveDurabilityUnconfirmed;
    let outcome = classify_passphrase_error(&err);
    let effect = PassphraseWorkerEffect::Failure(outcome);
    let dispatch = compose_passphrase_dispatch(&busy, &effect);
    assert_eq!(
        dispatch.new_is_encrypted, None,
        "the dialog stays open on failure — no mode-flag flip",
    );
}

// ---------------------------------------------------------------------------
// passphrase_should_arm_idle_after — re-asks
// `paladin_core::policy::auto_lock::IdlePolicy::should_arm` after a
// successful passphrase transition, so the auto-lock timer state
// tracks the new on-disk mode without re-inspecting the file.
//
// Encrypted-only gating lives in `IdlePolicy` itself: a plaintext
// vault (post-`Remove`) returns `false` regardless of the user's
// `auto_lock_enabled` setting. The helper threads the projection
// through `passphrase_new_is_encrypted_after`, so failures (which
// project `None`) are also `None` here.
// ---------------------------------------------------------------------------

#[test]
fn passphrase_should_arm_idle_after_success_encrypted_consults_idle_policy() {
    use paladin_core::policy::auto_lock::IdlePolicy;
    use paladin_gtk::app::state::passphrase_should_arm_idle_after;
    use paladin_gtk::passphrase_dialog::{PassphraseWorkerEffect, SubFlow};

    let (_tempdir, _path, vault, _store) = fresh_plaintext_pair();
    let effect = PassphraseWorkerEffect::Success {
        sub_flow: SubFlow::Set,
        new_is_encrypted: true,
    };
    let observed = passphrase_should_arm_idle_after(&effect, vault.settings());
    assert_eq!(
        observed,
        Some(IdlePolicy::should_arm(true, vault.settings())),
        "Set success must consult IdlePolicy::should_arm with the new encrypted flag",
    );
}

#[test]
fn passphrase_should_arm_idle_after_success_plaintext_returns_some_false() {
    use paladin_gtk::app::state::passphrase_should_arm_idle_after;
    use paladin_gtk::passphrase_dialog::{PassphraseWorkerEffect, SubFlow};

    // `Remove` flips the vault to plaintext. `IdlePolicy::should_arm`
    // returns `false` for plaintext regardless of the
    // `auto_lock_enabled` setting (DESIGN §6 / §7 plaintext no-op),
    // so the helper must surface that as `Some(false)`.
    let (_tempdir, _path, vault, _store) = fresh_plaintext_pair();
    let effect = PassphraseWorkerEffect::Success {
        sub_flow: SubFlow::Remove,
        new_is_encrypted: false,
    };
    let observed = passphrase_should_arm_idle_after(&effect, vault.settings());
    assert_eq!(
        observed,
        Some(false),
        "Remove success on a plaintext vault must not arm the auto-lock timer",
    );
}

#[test]
fn passphrase_should_arm_idle_after_failure_returns_none() {
    use paladin_gtk::app::state::passphrase_should_arm_idle_after;
    use paladin_gtk::passphrase_dialog::{classify_passphrase_error, PassphraseWorkerEffect};

    let (_tempdir, _path, vault, _store) = fresh_plaintext_pair();
    let err = paladin_core::PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let outcome = classify_passphrase_error(&err);
    let effect = PassphraseWorkerEffect::Failure(outcome);
    let observed = passphrase_should_arm_idle_after(&effect, vault.settings());
    assert_eq!(
        observed, None,
        "Failures keep the dialog open — no re-arm decision to take",
    );
}

// ---------------------------------------------------------------------------
// SettingsComponent dispatch composers — pre-worker `Unlocked →
// UnlockedBusy` busy-gate, `compose_settings_worker_input` bundling,
// `compose_settings_dispatch` aggregator over the typed
// `SettingsWorkerEffect`.
//
// Per `IMPLEMENTATION_PLAN_04_GTK.md` §"SettingsComponent" L3443+:
// live-apply through `Vault::mutate_and_save`; dialog stays mounted
// across every save; success raises an `AdwToast`; auto-lock
// changes re-ask `IdlePolicy::should_arm`.
// ---------------------------------------------------------------------------

#[test]
fn submit_settings_app_state_from_unlocked_returns_unlocked_busy_preserving_path() {
    use paladin_gtk::app::state::submit_settings_app_state;
    let path = vault_path();
    let unlocked = AppState::Unlocked { path: path.clone() };
    let next = submit_settings_app_state(&unlocked)
        .expect("Unlocked must transition to UnlockedBusy on settings submit");
    assert!(matches!(next, AppState::UnlockedBusy { .. }));
    assert_path_eq(&next, &path);
}

#[test]
fn submit_settings_app_state_from_non_unlocked_returns_none() {
    use paladin_gtk::app::state::submit_settings_app_state;
    let path = vault_path();
    assert!(submit_settings_app_state(&AppState::Missing { path: path.clone() }).is_none());
    assert!(submit_settings_app_state(&AppState::Locked { path: path.clone() }).is_none());
    assert!(submit_settings_app_state(&AppState::UnlockedBusy { path: path.clone() }).is_none());
    let startup = decide_state_from_inspect(&path, Err(invalid_header_err()))
        .expect("inspect Err yields StartupError state");
    assert!(submit_settings_app_state(&startup).is_none());
}

#[test]
fn apply_submit_settings_inplace_from_unlocked_mutates_to_unlocked_busy_and_returns_true() {
    use paladin_gtk::app::state::apply_submit_settings_inplace;
    let path = vault_path();
    let mut state = AppState::Unlocked { path: path.clone() };
    let mutated = apply_submit_settings_inplace(&mut state);
    assert!(mutated);
    assert!(matches!(state, AppState::UnlockedBusy { .. }));
    assert_path_eq(&state, &path);
}

#[test]
fn apply_submit_settings_inplace_from_non_unlocked_returns_false_and_keeps_state() {
    use paladin_gtk::app::state::apply_submit_settings_inplace;
    let path = vault_path();
    for variant in [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::UnlockedBusy { path: path.clone() },
    ] {
        let mut state = variant.clone();
        let mutated = apply_submit_settings_inplace(&mut state);
        assert!(!mutated);
        match (&state, &variant) {
            (AppState::Missing { .. }, AppState::Missing { .. })
            | (AppState::Locked { .. }, AppState::Locked { .. })
            | (AppState::UnlockedBusy { .. }, AppState::UnlockedBusy { .. }) => {}
            other => panic!("source variant must be preserved, got {other:?}"),
        }
    }
}

#[test]
#[allow(clippy::similar_names)]
fn compose_settings_worker_input_from_unlocked_bundles_pair_and_patch() {
    use paladin_gtk::app::state::compose_settings_worker_input;
    let (_tempdir, path, vault, store) = fresh_plaintext_pair();
    let unlocked = AppState::Unlocked { path: path.clone() };
    let patch = paladin_core::SettingPatch::AutoLockEnabled(true);

    let input = compose_settings_worker_input(&unlocked, (vault, store), patch)
        .expect("Unlocked source must produce a SettingsWorkerInput");
    assert_eq!(
        input.patch,
        paladin_core::SettingPatch::AutoLockEnabled(true)
    );
    assert_eq!(input.vault.summaries().count(), 0);
}

#[test]
#[allow(clippy::similar_names)]
fn compose_settings_worker_input_from_non_unlocked_returns_pair_back() {
    use paladin_gtk::app::state::compose_settings_worker_input;
    for variant in ["missing", "locked", "unlocked_busy", "startup_error"] {
        let (_tempdir, path, vault, store) = fresh_plaintext_pair();
        let source = match variant {
            "missing" => AppState::Missing { path: path.clone() },
            "locked" => AppState::Locked { path: path.clone() },
            "unlocked_busy" => AppState::UnlockedBusy { path: path.clone() },
            "startup_error" => decide_state_from_inspect(&path, Err(invalid_header_err()))
                .expect("inspect Err yields StartupError state"),
            _ => unreachable!(),
        };
        let result = compose_settings_worker_input(
            &source,
            (vault, store),
            paladin_core::SettingPatch::AutoLockEnabled(true),
        );
        assert!(
            result.is_err(),
            "non-Unlocked source must return Err(pair), variant={variant}",
        );
        let (returned_vault, _returned_store) = result.err().unwrap();
        assert_eq!(returned_vault.summaries().count(), 0);
    }
}

#[test]
fn apply_settings_vault_install_inplace_writes_pair_into_empty_slot() {
    use paladin_gtk::app::state::apply_settings_vault_install_inplace;
    let (_tempdir, _path, vault, store) = fresh_plaintext_pair();
    let mut slot: Option<(Vault, Store)> = None;
    apply_settings_vault_install_inplace(&mut slot, (vault, store));
    assert!(slot.is_some());
}

#[test]
fn apply_settings_vault_install_inplace_replaces_existing_slot() {
    use paladin_gtk::app::state::apply_settings_vault_install_inplace;
    let (_tempdir1, _path1, vault1, store1) = fresh_plaintext_pair();
    let (_tempdir2, _path2, vault2, store2) = fresh_plaintext_pair();
    let mut slot: Option<(Vault, Store)> = Some((vault1, store1));
    apply_settings_vault_install_inplace(&mut slot, (vault2, store2));
    assert!(slot.is_some());
}

// ---------------------------------------------------------------------------
// compose_settings_dispatch — aggregates app_state rollback,
// dialog_msg forward, success_toast, and reask_idle projections from
// the typed `SettingsWorkerEffect`.
// ---------------------------------------------------------------------------

fn settings_effect_success_auto_lock_enabled(
    value: bool,
) -> paladin_gtk::settings::SettingsWorkerEffect {
    paladin_gtk::settings::SettingsWorkerEffect {
        change: paladin_gtk::settings::AcceptedChange::AutoLockEnabled(value),
        outcome: paladin_gtk::settings::SaveOutcome::Success,
    }
}

fn settings_effect_success_clipboard_clear_enabled(
    value: bool,
) -> paladin_gtk::settings::SettingsWorkerEffect {
    paladin_gtk::settings::SettingsWorkerEffect {
        change: paladin_gtk::settings::AcceptedChange::ClipboardClearEnabled(value),
        outcome: paladin_gtk::settings::SaveOutcome::Success,
    }
}

fn settings_effect_rollback_auto_lock_secs(
    value: u32,
) -> paladin_gtk::settings::SettingsWorkerEffect {
    use paladin_gtk::settings::InlineError;
    let err = paladin_core::PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    paladin_gtk::settings::SettingsWorkerEffect {
        change: paladin_gtk::settings::AcceptedChange::AutoLockSecs(value),
        outcome: paladin_gtk::settings::SaveOutcome::Rollback {
            error: InlineError::from_error(&err),
            field: paladin_gtk::settings::SettingsField::AutoLockSecs,
        },
    }
}

fn settings_effect_durability_warning_auto_lock_enabled(
    value: bool,
) -> paladin_gtk::settings::SettingsWorkerEffect {
    use paladin_gtk::settings::InlineWarning;
    let err = paladin_core::PaladinError::SaveDurabilityUnconfirmed;
    paladin_gtk::settings::SettingsWorkerEffect {
        change: paladin_gtk::settings::AcceptedChange::AutoLockEnabled(value),
        outcome: paladin_gtk::settings::SaveOutcome::DurabilityWarning {
            warning: InlineWarning::from_error(&err),
            field: paladin_gtk::settings::SettingsField::AutoLockEnabled,
        },
    }
}

fn settings_effect_inline_clipboard_clear_secs(
    value: u32,
) -> paladin_gtk::settings::SettingsWorkerEffect {
    use paladin_gtk::settings::InlineError;
    let err = paladin_core::PaladinError::IoError {
        operation: "rename",
        source: io::Error::other("synthetic"),
    };
    paladin_gtk::settings::SettingsWorkerEffect {
        change: paladin_gtk::settings::AcceptedChange::ClipboardClearSecs(value),
        outcome: paladin_gtk::settings::SaveOutcome::Inline {
            error: InlineError::from_error(&err),
            field: paladin_gtk::settings::SettingsField::ClipboardClearSecs,
        },
    }
}

#[test]
fn compose_settings_dispatch_success_rolls_busy_back_and_forwards_worker_completed() {
    use paladin_gtk::app::state::compose_settings_dispatch;
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path: path.clone() };
    let dispatch =
        compose_settings_dispatch(&busy, &settings_effect_success_auto_lock_enabled(true));
    assert!(
        matches!(dispatch.app_state, Some(AppState::Unlocked { .. })),
        "Success must roll the busy gate back to Unlocked",
    );
    assert!(
        matches!(
            dispatch.dialog_msg,
            Some(paladin_gtk::settings::SettingsDialogMsg::WorkerCompleted(_))
        ),
        "Every effect forwards WorkerCompleted so the dialog stays in sync",
    );
    assert!(
        dispatch.success_toast.is_some(),
        "Success must raise the settings-saved AdwToast",
    );
}

#[test]
fn compose_settings_dispatch_success_clipboard_does_not_reask_idle() {
    use paladin_gtk::app::state::compose_settings_dispatch;
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path };
    let dispatch = compose_settings_dispatch(
        &busy,
        &settings_effect_success_clipboard_clear_enabled(true),
    );
    assert!(
        !dispatch.reask_idle,
        "Clipboard-clear changes never affect IdlePolicy — reask_idle must stay false",
    );
}

#[test]
fn compose_settings_dispatch_success_auto_lock_reasks_idle() {
    use paladin_gtk::app::state::compose_settings_dispatch;
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path };
    let dispatch =
        compose_settings_dispatch(&busy, &settings_effect_success_auto_lock_enabled(true));
    assert!(
        dispatch.reask_idle,
        "Auto-lock change with committed outcome must re-ask IdlePolicy::should_arm",
    );
}

#[test]
fn compose_settings_dispatch_durability_warning_keeps_committed_and_reasks_idle() {
    use paladin_gtk::app::state::compose_settings_dispatch;
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path };
    let dispatch = compose_settings_dispatch(
        &busy,
        &settings_effect_durability_warning_auto_lock_enabled(true),
    );
    assert!(
        dispatch.success_toast.is_none(),
        "DurabilityWarning attaches to the row body, not the toast surface",
    );
    assert!(
        dispatch.reask_idle,
        "DurabilityWarning still committed the value to disk — re-ask IdlePolicy",
    );
}

#[test]
fn compose_settings_dispatch_rollback_does_not_reask_idle() {
    use paladin_gtk::app::state::compose_settings_dispatch;
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path };
    let dispatch = compose_settings_dispatch(&busy, &settings_effect_rollback_auto_lock_secs(120));
    assert!(
        dispatch.success_toast.is_none(),
        "Rollback inline-renders the error on the row; no toast",
    );
    assert!(
        !dispatch.reask_idle,
        "Rollback leaves on-disk policy unchanged — IdlePolicy must not be re-asked",
    );
    assert!(
        matches!(dispatch.app_state, Some(AppState::Unlocked { .. })),
        "Busy gate rolls back even on Rollback",
    );
}

#[test]
fn compose_settings_dispatch_inline_does_not_reask_idle() {
    use paladin_gtk::app::state::compose_settings_dispatch;
    let path = vault_path();
    let busy = AppState::UnlockedBusy { path };
    let dispatch =
        compose_settings_dispatch(&busy, &settings_effect_inline_clipboard_clear_secs(60));
    assert!(
        dispatch.success_toast.is_none(),
        "Inline-error attaches to the row body",
    );
    assert!(
        !dispatch.reask_idle,
        "Clipboard change with inline error never re-asks IdlePolicy",
    );
}

#[test]
fn compose_settings_dispatch_from_non_unlocked_busy_returns_no_app_state() {
    use paladin_gtk::app::state::compose_settings_dispatch;
    let path = vault_path();
    let effect = settings_effect_success_auto_lock_enabled(true);
    for source in [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
    ] {
        let dispatch = compose_settings_dispatch(&source, &effect);
        assert!(
            dispatch.app_state.is_none(),
            "non-UnlockedBusy source must not install a phantom Unlocked",
        );
    }
}

#[test]
fn apply_settings_dispatch_inplace_applies_unlocked_rollback() {
    use paladin_gtk::app::state::{apply_settings_dispatch_inplace, compose_settings_dispatch};
    let path = vault_path();
    let mut state = AppState::UnlockedBusy { path: path.clone() };
    let dispatch =
        compose_settings_dispatch(&state, &settings_effect_success_auto_lock_enabled(true));
    let mutated = apply_settings_dispatch_inplace(&mut state, &dispatch);
    assert!(mutated);
    assert!(matches!(state, AppState::Unlocked { .. }));
    assert_path_eq(&state, &path);
}

#[test]
fn apply_settings_dispatch_inplace_noop_when_app_state_is_none() {
    use paladin_gtk::app::state::{apply_settings_dispatch_inplace, compose_settings_dispatch};
    let path = vault_path();
    let mut state = AppState::Unlocked { path: path.clone() };
    let dispatch =
        compose_settings_dispatch(&state, &settings_effect_success_auto_lock_enabled(true));
    let mutated = apply_settings_dispatch_inplace(&mut state, &dispatch);
    assert!(!mutated);
    assert!(matches!(state, AppState::Unlocked { .. }));
}

// ---------------------------------------------------------------------------
// run_settings_worker — `gio::spawn_blocking` body that runs
// `Vault::mutate_and_save(|v| v.apply_setting_patch(patch))` and
// classifies the typed result through `classify_settings_save_result`.
//
// Exercised against tempfile-backed plaintext vaults so the full
// round-trip (mutate + persist + reopen) is asserted; no GTK /
// libadwaita main loop required.
// ---------------------------------------------------------------------------

#[test]
fn run_settings_worker_success_persists_auto_lock_enabled_change() {
    use paladin_gtk::settings::{run_settings_worker, SaveOutcome, SettingsWorkerInput};

    let (_tempdir, vault_file, vault, store) = fresh_plaintext_pair();
    let prior_enabled = vault.settings().auto_lock_enabled();
    let patch = paladin_core::SettingPatch::AutoLockEnabled(!prior_enabled);

    let completion = run_settings_worker(SettingsWorkerInput {
        vault,
        store,
        patch,
    });
    assert!(
        matches!(completion.effect.outcome, SaveOutcome::Success),
        "AutoLockEnabled flip on a tempfile vault must succeed",
    );
    assert_eq!(
        completion.vault.settings().auto_lock_enabled(),
        !prior_enabled,
        "The returned vault carries the applied patch",
    );

    // Reopen from disk to confirm the persist actually happened.
    let (reopened, _store) =
        paladin_core::Store::open(&vault_file, paladin_core::VaultLock::Plaintext)
            .expect("reopen plaintext vault after settings save");
    assert_eq!(
        reopened.settings().auto_lock_enabled(),
        !prior_enabled,
        "The on-disk vault carries the applied patch after run_settings_worker",
    );
}

#[test]
fn run_settings_worker_success_persists_clipboard_clear_secs_change() {
    use paladin_gtk::settings::{run_settings_worker, SaveOutcome, SettingsWorkerInput};

    let (_tempdir, _path, vault, store) = fresh_plaintext_pair();
    let target = paladin_core::CLIPBOARD_CLEAR_SECS_MAX;
    let patch = paladin_core::SettingPatch::ClipboardClearSecs(target);

    let completion = run_settings_worker(SettingsWorkerInput {
        vault,
        store,
        patch,
    });
    assert!(matches!(completion.effect.outcome, SaveOutcome::Success));
    assert_eq!(completion.vault.settings().clipboard_clear_secs(), target);
}
