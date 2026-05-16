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
    apply_unlock_failure_action, decide_state_from_inspect, decide_state_from_open_error,
    decide_state_from_path_resolution, decide_unlock_failure_action, AppState, OpenErrorOutcome,
    UnlockFailureAction, UnlockFailureEffect,
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
