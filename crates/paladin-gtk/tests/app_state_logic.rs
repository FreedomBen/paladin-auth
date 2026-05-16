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

use paladin_core::{
    format_unsafe_permissions, ErrorKind, PaladinError, PermissionSubject, VaultMode, VaultStatus,
};

use paladin_gtk::app::state::{
    apply_submit_unlock_inplace, apply_unlock_dispatch_inplace, apply_unlock_failure_action,
    compose_unlock_dispatch, decide_state_from_inspect, decide_state_from_open_error,
    decide_state_from_path_resolution, decide_unlock_failure_action, decide_unlock_success_state,
    route_unlock_failure_effect, route_unlock_success_effect, route_unlock_worker_outcome,
    should_drop_unlock_dialog_after, submit_unlock_app_state, unlock_app_state_after,
    unlock_dialog_msg_after, unlock_final_app_state, AppState, OpenErrorOutcome,
    UnlockFailureAction, UnlockFailureEffect, UnlockSuccessEffect, UnlockWorkerEffect,
};
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
