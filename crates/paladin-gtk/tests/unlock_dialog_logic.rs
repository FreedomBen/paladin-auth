// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic unlock-dialog tests for `paladin-gtk`.
//!
//! `UnlockComponent` is the passphrase-entry view that `AppModel`
//! presents whenever `paladin_core::inspect` reports
//! [`paladin_core::VaultStatus::Encrypted`]. Per
//! `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
//! `UnlockComponent` and §"Vault interaction", the view is
//! conditional on the vault being encrypted (plaintext vaults skip
//! it entirely), the submit handler builds a
//! [`paladin_core::VaultLock::Encrypted`] from the typed passphrase
//! and hands it to `paladin_core::open` on `gio::spawn_blocking`,
//! and the worker outcome is routed:
//!
//! * Wrong passphrase (`decrypt_failed` AEAD authentication failure
//!   or `invalid_passphrase` `zero_length` pre-KDF rejection) stays
//!   inline at the passphrase row.
//! * Every other open failure (`unsafe_permissions`,
//!   `wrong_vault_lock`, `invalid_header`, `invalid_payload`,
//!   `unsupported_format_version`, `kdf_params_out_of_bounds`,
//!   `io_error`) transitions `AppModel` to
//!   `StartupErrorComponent` via the shared
//!   [`paladin_gtk::startup_error::classify_open_error`].
//!
//! The pure-logic module under test (`paladin_gtk::unlock_dialog`)
//! owns the gating, pre-submit rejection (empty passphrase), and
//! [`paladin_core::VaultLock`] construction so the GTK widget layer
//! can stay a thin shell over the decisions.

use std::io;
use std::path::Path;

use paladin_core::{ErrorKind, PaladinError, PermissionSubject, VaultLock, VaultMode, VaultStatus};

use paladin_gtk::secret_fields::SecretEntry;
use paladin_gtk::startup_error::{OpenErrorRouting, StartupErrorSource};
use paladin_gtk::unlock_dialog::{
    apply_msg, classify_unlock_error, prepare_unlock_lock, unlock_view_required, InlineError,
    SubmitRejection, UnlockDialogMsg, UnlockDialogOutput, UnlockDialogState,
};

// ---------------------------------------------------------------------------
// unlock_view_required: encrypted vaults only
// ---------------------------------------------------------------------------

#[test]
fn unlock_view_required_for_encrypted_status() {
    assert!(unlock_view_required(VaultStatus::Encrypted));
}

#[test]
fn unlock_view_skipped_for_plaintext_status() {
    assert!(!unlock_view_required(VaultStatus::Plaintext));
}

#[test]
fn unlock_view_skipped_for_missing_status() {
    // `Missing` routes to `InitDialog`, never to `UnlockComponent`.
    assert!(!unlock_view_required(VaultStatus::Missing));
}

// ---------------------------------------------------------------------------
// prepare_unlock_lock: pre-submit gating
// ---------------------------------------------------------------------------

#[test]
fn prepare_unlock_lock_empty_passphrase_rejects() {
    let err = prepare_unlock_lock("").expect_err("empty passphrase must reject");
    assert_eq!(err, SubmitRejection::EmptyPassphrase);
}

#[test]
fn prepare_unlock_lock_non_empty_builds_encrypted_lock() {
    let lock = prepare_unlock_lock("hunter2").expect("non-empty passphrase must build VaultLock");
    match lock {
        VaultLock::Encrypted(_) => {}
        other => panic!("expected VaultLock::Encrypted, got {other:?}"),
    }
}

#[test]
fn prepare_unlock_lock_preserves_passphrase_bytes() {
    use secrecy::ExposeSecret;
    let lock = prepare_unlock_lock("hunter2").expect("non-empty passphrase must build VaultLock");
    match lock {
        VaultLock::Encrypted(secret) => {
            assert_eq!(secret.expose_secret(), "hunter2");
        }
        other => panic!("expected VaultLock::Encrypted, got {other:?}"),
    }
}

#[test]
fn prepare_unlock_lock_accepts_whitespace_only_passphrase() {
    // Whitespace is a valid passphrase byte — only the *empty* string is
    // rejected pre-flight. paladin_core decides on whitespace content.
    let lock = prepare_unlock_lock("   ").expect("whitespace-only passphrase must build VaultLock");
    assert!(matches!(lock, VaultLock::Encrypted(_)));
}

// ---------------------------------------------------------------------------
// SubmitRejection: §5 error_kind / reason mapping
// ---------------------------------------------------------------------------

#[test]
fn submit_rejection_empty_passphrase_maps_to_invalid_passphrase() {
    let rej = SubmitRejection::EmptyPassphrase;
    assert_eq!(rej.error_kind(), ErrorKind::InvalidPassphrase);
}

#[test]
fn submit_rejection_empty_passphrase_reason_is_zero_length() {
    // §5 `invalid_passphrase.reason` field for empty passphrase
    // matches `paladin_core::PaladinError::InvalidPassphrase { reason:
    // "zero_length" }` so the GUI surfaces the same stable reason
    // code the CLI / TUI do.
    let rej = SubmitRejection::EmptyPassphrase;
    assert_eq!(rej.reason(), "zero_length");
}

// ---------------------------------------------------------------------------
// classify_unlock_error: wrong-passphrase inline; everything else → Startup
// ---------------------------------------------------------------------------

#[test]
fn classify_unlock_error_decrypt_failed_stays_inline() {
    let err = PaladinError::DecryptFailed;
    let routing = classify_unlock_error(&err);
    assert!(
        matches!(routing, OpenErrorRouting::InlinePassphrase),
        "decrypt_failed must surface inline at the passphrase entry, got {routing:?}",
    );
}

#[test]
fn classify_unlock_error_invalid_passphrase_stays_inline() {
    let err = PaladinError::InvalidPassphrase {
        reason: "zero_length",
    };
    let routing = classify_unlock_error(&err);
    assert!(
        matches!(routing, OpenErrorRouting::InlinePassphrase),
        "invalid_passphrase must surface inline at the passphrase entry, got {routing:?}",
    );
}

#[test]
fn classify_unlock_error_unsafe_permissions_routes_to_startup() {
    let err = PaladinError::UnsafePermissions {
        path: std::path::PathBuf::from("/tmp/vault.bin"),
        subject: PermissionSubject::VaultFile,
        actual_mode: "0644".to_string(),
        expected_mode: "0600".to_string(),
    };
    match classify_unlock_error(&err) {
        OpenErrorRouting::Startup(startup) => {
            assert_eq!(startup.source, StartupErrorSource::Open);
            assert_eq!(startup.kind, ErrorKind::UnsafePermissions);
            // §4.7: `unsafe_permissions` rendering must match
            // `paladin_core::format_unsafe_permissions` verbatim so
            // wording is identical to the CLI / TUI.
            let expected = paladin_core::format_unsafe_permissions(&err)
                .expect("UnsafePermissions formatter returns Some");
            assert_eq!(startup.rendered, expected);
        }
        OpenErrorRouting::InlinePassphrase => {
            panic!("unsafe_permissions must route to StartupErrorComponent, not stay inline")
        }
    }
}

#[test]
fn classify_unlock_error_wrong_vault_lock_routes_to_startup() {
    let err = PaladinError::WrongVaultLock {
        expected: VaultMode::Plaintext,
        actual: VaultMode::Encrypted,
    };
    match classify_unlock_error(&err) {
        OpenErrorRouting::Startup(startup) => {
            assert_eq!(startup.source, StartupErrorSource::Open);
            assert_eq!(startup.kind, ErrorKind::WrongVaultLock);
        }
        OpenErrorRouting::InlinePassphrase => {
            panic!("wrong_vault_lock must route to StartupErrorComponent, not stay inline")
        }
    }
}

#[test]
fn classify_unlock_error_invalid_header_routes_to_startup() {
    let err = PaladinError::InvalidHeader;
    match classify_unlock_error(&err) {
        OpenErrorRouting::Startup(startup) => {
            assert_eq!(startup.kind, ErrorKind::InvalidHeader);
        }
        OpenErrorRouting::InlinePassphrase => {
            panic!("invalid_header must route to StartupErrorComponent, not stay inline")
        }
    }
}

#[test]
fn classify_unlock_error_invalid_payload_routes_to_startup() {
    let err = PaladinError::InvalidPayload {
        reason: "decode_failed",
    };
    match classify_unlock_error(&err) {
        OpenErrorRouting::Startup(startup) => {
            assert_eq!(startup.kind, ErrorKind::InvalidPayload);
        }
        OpenErrorRouting::InlinePassphrase => {
            panic!("invalid_payload must route to StartupErrorComponent, not stay inline")
        }
    }
}

#[test]
fn classify_unlock_error_unsupported_format_version_routes_to_startup() {
    let err = PaladinError::UnsupportedFormatVersion { format_ver: 99 };
    match classify_unlock_error(&err) {
        OpenErrorRouting::Startup(startup) => {
            assert_eq!(startup.kind, ErrorKind::UnsupportedFormatVersion);
        }
        OpenErrorRouting::InlinePassphrase => {
            panic!("unsupported_format_version must route to StartupErrorComponent")
        }
    }
}

#[test]
fn classify_unlock_error_kdf_params_out_of_bounds_routes_to_startup() {
    let err = PaladinError::KdfParamsOutOfBounds {
        m_kib: 0,
        t: 0,
        p: 0,
    };
    match classify_unlock_error(&err) {
        OpenErrorRouting::Startup(startup) => {
            assert_eq!(startup.kind, ErrorKind::KdfParamsOutOfBounds);
        }
        OpenErrorRouting::InlinePassphrase => {
            panic!("kdf_params_out_of_bounds must route to StartupErrorComponent")
        }
    }
}

#[test]
fn classify_unlock_error_io_error_routes_to_startup() {
    let err = PaladinError::IoError {
        operation: "read_vault_file",
        source: io::Error::new(io::ErrorKind::PermissionDenied, "denied"),
    };
    match classify_unlock_error(&err) {
        OpenErrorRouting::Startup(startup) => {
            assert_eq!(startup.kind, ErrorKind::IoError);
            assert_eq!(startup.source, StartupErrorSource::Open);
        }
        OpenErrorRouting::InlinePassphrase => {
            panic!("io_error must route to StartupErrorComponent, not stay inline")
        }
    }
}

// ---------------------------------------------------------------------------
// Passphrase entry zeroization — the GTK `EntryBuffer` shadows into a
// `SecretEntry` (`Zeroizing<String>`) so submit/cancel/close/auto-lock
// clear the secret bytes in place. The actual zeroize-on-drop guarantee
// is exercised in `tests/secret_fields_logic.rs`; this check just
// confirms that the unlock-dialog widget layer can call the shared
// helper without needing a dedicated buffer type.
// ---------------------------------------------------------------------------

#[test]
fn passphrase_entry_clears_on_submit() {
    let mut entry = SecretEntry::from("hunter2");
    assert_eq!(entry.text(), "hunter2");
    entry.clear();
    assert!(entry.text().is_empty());
    assert!(entry.is_empty());
}

#[test]
fn passphrase_entry_take_returns_zeroizing_value() {
    let mut entry = SecretEntry::from("hunter2");
    let taken = entry.take();
    assert_eq!(taken.as_str(), "hunter2");
    // After `take`, the entry is empty so subsequent submit reuses an
    // empty buffer that pre-submit rejection short-circuits.
    assert!(entry.is_empty());
    let rej = prepare_unlock_lock(entry.text())
        .expect_err("empty entry must reject pre-flight after take");
    assert_eq!(rej, SubmitRejection::EmptyPassphrase);
}

#[test]
fn passphrase_entry_set_then_clear_round_trips() {
    // `set` mirrors the GTK `EntryBuffer` shadow path: the widget
    // layer pushes every keystroke into the Paladin-owned
    // `Zeroizing<String>`. After `clear`, no bytes remain.
    let mut entry = SecretEntry::new();
    entry.set("hunter2");
    assert_eq!(entry.text(), "hunter2");
    entry.clear();
    assert!(entry.text().is_empty());
}

// ---------------------------------------------------------------------------
// UnlockDialogState: live passphrase shadow buffer driven by the
// `adw::PasswordEntryRow` text-change signal. The state owns a
// `SecretEntry` (Zeroizing<String>) shadow copy so cleartext bytes
// live in Paladin-owned memory rather than escaping into AppMsg /
// AppOutput. The widget submit / worker / decrypt-failed inline error
// land in a follow-up commit alongside the `UnlockedBusy` worker
// infrastructure; this milestone wires only the entry-row shadow path.
// ---------------------------------------------------------------------------

#[test]
fn unlock_dialog_state_new_is_empty() {
    let state = UnlockDialogState::new();
    assert!(
        state.is_passphrase_empty(),
        "freshly-constructed state must report an empty passphrase",
    );
    assert!(
        state.passphrase_text().is_empty(),
        "freshly-constructed state must read back as an empty &str",
    );
}

#[test]
fn unlock_dialog_state_default_matches_new() {
    let state = UnlockDialogState::default();
    assert!(state.is_passphrase_empty());
    assert!(state.passphrase_text().is_empty());
}

#[test]
fn unlock_dialog_state_set_passphrase_shadows_typed_bytes() {
    let mut state = UnlockDialogState::new();
    state.set_passphrase("hunter2");
    assert_eq!(state.passphrase_text(), "hunter2");
    assert!(!state.is_passphrase_empty());
}

#[test]
fn unlock_dialog_state_set_passphrase_replaces_previous() {
    // `connect_changed` fires on every keystroke; the shadow buffer
    // must atomically replace, not append.
    let mut state = UnlockDialogState::new();
    state.set_passphrase("first");
    state.set_passphrase("second");
    assert_eq!(state.passphrase_text(), "second");
}

#[test]
fn unlock_dialog_state_set_passphrase_to_empty_reports_empty() {
    // Backspacing the entry back to "" must surface as an empty
    // passphrase so `prepare_unlock_lock` rejects pre-flight.
    let mut state = UnlockDialogState::new();
    state.set_passphrase("hunter2");
    state.set_passphrase("");
    assert!(state.is_passphrase_empty());
    assert_eq!(state.passphrase_text(), "");
}

#[test]
fn unlock_dialog_state_clear_passphrase_wipes_buffer() {
    // The widget's `update` calls `clear_passphrase` on submit /
    // cancel / auto-lock so cleartext bytes do not outlive the
    // event.
    let mut state = UnlockDialogState::new();
    state.set_passphrase("hunter2");
    state.clear_passphrase();
    assert!(state.is_passphrase_empty());
    assert_eq!(state.passphrase_text(), "");
}

#[test]
fn unlock_dialog_state_take_passphrase_returns_zeroizing_and_empties_state() {
    use zeroize::Zeroizing;
    let mut state = UnlockDialogState::new();
    state.set_passphrase("hunter2");
    let taken: Zeroizing<String> = state.take_passphrase();
    assert_eq!(taken.as_str(), "hunter2");
    assert!(state.is_passphrase_empty());
}

#[test]
fn unlock_dialog_state_passphrase_flows_into_prepare_unlock_lock() {
    // The widget's submit path will read `state.passphrase_text()`
    // and hand it to `prepare_unlock_lock`. Non-empty drafts build a
    // `VaultLock::Encrypted`.
    let mut state = UnlockDialogState::new();
    state.set_passphrase("hunter2");
    let lock =
        prepare_unlock_lock(state.passphrase_text()).expect("non-empty state must build VaultLock");
    assert!(matches!(lock, VaultLock::Encrypted(_)));
}

#[test]
fn unlock_dialog_state_empty_rejects_via_prepare_unlock_lock() {
    let state = UnlockDialogState::new();
    let rej = prepare_unlock_lock(state.passphrase_text())
        .expect_err("empty state must reject pre-flight");
    assert_eq!(rej, SubmitRejection::EmptyPassphrase);
}

// ---------------------------------------------------------------------------
// submit_button_sensitive — the "Unlock" button's `set_sensitive`
// binding. The widget's `#[watch] set_sensitive` reads this predicate
// so the empty-passphrase pre-flight short-circuit in
// `prepare_unlock_lock` never fires through a click. The contract is
// `!is_passphrase_empty()`; pinning it through a dedicated accessor
// keeps the widget binding stable as additional gating conditions
// (e.g. `UnlockedBusy` worker activity) land in follow-up commits.
// ---------------------------------------------------------------------------

#[test]
fn unlock_dialog_state_submit_button_sensitive_false_when_empty() {
    // Default state has an empty shadow buffer, so the "Unlock"
    // submit button must start disabled. The user has to type at
    // least one byte before the gate opens.
    let state = UnlockDialogState::new();
    assert!(!state.submit_button_sensitive());
}

#[test]
fn unlock_dialog_state_submit_button_sensitive_true_when_non_empty() {
    let mut state = UnlockDialogState::new();
    state.set_passphrase("hunter2");
    assert!(state.submit_button_sensitive());
}

#[test]
fn unlock_dialog_state_submit_button_sensitive_toggles_with_set_then_clear() {
    // The user types, then deletes everything — the button must
    // re-disable so a stray Enter cannot fire the empty-passphrase
    // pre-flight short-circuit.
    let mut state = UnlockDialogState::new();
    assert!(!state.submit_button_sensitive());
    state.set_passphrase("h");
    assert!(state.submit_button_sensitive());
    state.clear_passphrase();
    assert!(!state.submit_button_sensitive());
}

#[test]
fn unlock_dialog_state_submit_button_sensitive_false_after_take_passphrase() {
    // The future worker commit will call `take_passphrase` from the
    // Submit handler to consume the bytes into a `VaultLock`. After
    // the take, the state is empty, so the button must re-disable
    // until the worker returns (preventing a duplicate submit while
    // `UnlockedBusy` is active).
    let mut state = UnlockDialogState::new();
    state.set_passphrase("hunter2");
    assert!(state.submit_button_sensitive());
    let _ = state.take_passphrase();
    assert!(!state.submit_button_sensitive());
}

#[test]
fn unlock_dialog_state_submit_button_sensitive_matches_negated_is_passphrase_empty() {
    // The accessor is documented as `!is_passphrase_empty()`. Pin
    // that equivalence so future gating additions stay in sync with
    // the widget binding point.
    let mut state = UnlockDialogState::new();
    assert_eq!(
        state.submit_button_sensitive(),
        !state.is_passphrase_empty()
    );
    state.set_passphrase("hunter2");
    assert_eq!(
        state.submit_button_sensitive(),
        !state.is_passphrase_empty()
    );
}

// ---------------------------------------------------------------------------
// UnlockDialogMsg::PassphraseChanged — emitted by the entry row's
// `connect_changed` signal on every keystroke. The handler shadows
// the typed bytes into the SecretEntry buffer above.
// ---------------------------------------------------------------------------

#[test]
fn unlock_dialog_msg_passphrase_changed_carries_typed_text() {
    // Construct the variant in a test to confirm the public payload
    // shape matches `String` so the GTK signal handler can hand the
    // entry's `.text().to_string()` through unmodified.
    let msg = UnlockDialogMsg::PassphraseChanged("hunter2".to_string());
    match msg {
        UnlockDialogMsg::PassphraseChanged(text) => assert_eq!(text, "hunter2"),
        UnlockDialogMsg::SubmitClicked => panic!("expected PassphraseChanged, got SubmitClicked"),
    }
}

// ---------------------------------------------------------------------------
// InlineError — rendered representation of an `OpenErrorRouting::InlinePassphrase`
// outcome. The widget binds a `gtk::Label` to
// `UnlockDialogState::inline_error()` and renders the `.rendered` text
// while the option is `Some`. Errors are populated by the future
// `gio::spawn_blocking paladin_core::open` worker (deferred); this
// milestone wires the rendering surface so the follow-up commit only
// needs to flip the state.
// ---------------------------------------------------------------------------

#[test]
fn inline_error_from_decrypt_failed_renders_display_text() {
    // `decrypt_failed` (AEAD authentication failure) is the canonical
    // wrong-passphrase outcome. The dialog renders the typed §5
    // `PaladinError::Display` text unchanged so the wording matches
    // the CLI / TUI verbatim.
    let err = PaladinError::DecryptFailed;
    let inline = InlineError::from_error(&err);
    assert_eq!(inline.kind, ErrorKind::DecryptFailed);
    assert_eq!(inline.rendered, err.to_string());
    assert!(
        !inline.rendered.is_empty(),
        "DecryptFailed display text must be non-empty",
    );
}

#[test]
fn inline_error_from_invalid_passphrase_renders_display_text() {
    // `invalid_passphrase` covers the pre-KDF empty-passphrase short
    // circuit. `prepare_unlock_lock` rejects empty entries before any
    // worker spawns, but the inline error rendering still needs to
    // exist for defensive parity (e.g. a future code path that calls
    // `paladin_core::open` directly with a zero-length passphrase).
    let err = PaladinError::InvalidPassphrase {
        reason: "zero_length",
    };
    let inline = InlineError::from_error(&err);
    assert_eq!(inline.kind, ErrorKind::InvalidPassphrase);
    assert_eq!(inline.rendered, err.to_string());
}

#[test]
fn inline_error_is_clone() {
    // `UnlockDialogState::inline_error()` returns `Option<&InlineError>`
    // but reactive state often clones for use in `#[watch]` bindings.
    // Defensive: pin the `Clone` derive so accidental removal trips a
    // test instead of breaking the binding silently.
    let err = PaladinError::DecryptFailed;
    let inline = InlineError::from_error(&err);
    let cloned = inline.clone();
    assert_eq!(cloned.kind, inline.kind);
    assert_eq!(cloned.rendered, inline.rendered);
}

// ---------------------------------------------------------------------------
// InlineError::from_rejection — render the pre-flight `SubmitRejection`
// short-circuit inline beneath the passphrase entry. The "Unlock" submit
// button's `#[watch] set_sensitive` binding gates the click on
// `submit_button_sensitive()` (== `!is_passphrase_empty()`) so this path
// should never fire through a normal click. Defense-in-depth still
// matters: the future click handler will run `prepare_unlock_lock`
// regardless and stage this projection if the gate ever leaks (e.g. a
// keyboard accelerator firing before the property bindings settle, or a
// reactive race during `UnlockedBusy` window). The rendered wording
// must match `paladin_core::PaladinError::InvalidPassphrase { reason:
// "zero_length" }` verbatim so the GUI surfaces the same stable §5
// `error_kind` / `reason` pair the CLI / TUI do.
// ---------------------------------------------------------------------------

#[test]
fn inline_error_from_rejection_empty_passphrase_carries_invalid_passphrase_kind() {
    let inline = InlineError::from_rejection(SubmitRejection::EmptyPassphrase);
    assert_eq!(inline.kind, ErrorKind::InvalidPassphrase);
}

#[test]
fn inline_error_from_rejection_empty_passphrase_renders_zero_length_display() {
    // The rendered text must match the typed §5
    // `PaladinError::InvalidPassphrase { reason: "zero_length" }`
    // `Display` output verbatim so wording matches the CLI / TUI.
    let inline = InlineError::from_rejection(SubmitRejection::EmptyPassphrase);
    let expected = PaladinError::InvalidPassphrase {
        reason: "zero_length",
    }
    .to_string();
    assert_eq!(inline.rendered, expected);
}

#[test]
fn inline_error_from_rejection_matches_from_error_for_zero_length() {
    // `from_rejection(EmptyPassphrase)` must be field-for-field
    // identical to `from_error(&PaladinError::InvalidPassphrase {
    // reason: "zero_length" })`. Pinning the equivalence here means
    // the GTK widget layer can use either constructor without
    // diverging from the §5 stable error format.
    let from_rejection = InlineError::from_rejection(SubmitRejection::EmptyPassphrase);
    let from_error = InlineError::from_error(&PaladinError::InvalidPassphrase {
        reason: "zero_length",
    });
    assert_eq!(from_rejection.kind, from_error.kind);
    assert_eq!(from_rejection.rendered, from_error.rendered);
}

#[test]
fn inline_error_from_rejection_preserves_stable_reason_in_rendered_text() {
    // Defensive: the stable §5 `invalid_passphrase.reason` discriminator
    // must be visible in the rendered text so instrumentation /
    // accessibility tools can scrape the reason code without needing
    // structured error access.
    let inline = InlineError::from_rejection(SubmitRejection::EmptyPassphrase);
    assert!(
        inline
            .rendered
            .contains(SubmitRejection::EmptyPassphrase.reason()),
        "rendered text must surface the stable reason code, got {:?}",
        inline.rendered,
    );
}

// ---------------------------------------------------------------------------
// UnlockDialogState::inline_error — the live inline-error slot that the
// future worker commit populates from `classify_unlock_error` results
// and that the widget binds a `gtk::Label` to. Typing a new passphrase
// dismisses the prior error so the entry never carries a stale
// `decrypt_failed` message into the next attempt.
// ---------------------------------------------------------------------------

#[test]
fn unlock_dialog_state_inline_error_is_none_by_default() {
    let state = UnlockDialogState::new();
    assert!(
        state.inline_error().is_none(),
        "freshly-constructed state must report no inline error",
    );
}

#[test]
fn unlock_dialog_state_set_inline_error_stores_some() {
    let mut state = UnlockDialogState::new();
    let inline = InlineError::from_error(&PaladinError::DecryptFailed);
    state.set_inline_error(Some(inline.clone()));
    let stored = state.inline_error().expect("inline error must be Some");
    assert_eq!(stored.kind, inline.kind);
    assert_eq!(stored.rendered, inline.rendered);
}

#[test]
fn unlock_dialog_state_set_inline_error_none_clears() {
    // Defensive: after surfacing a `decrypt_failed`, the worker
    // commit's success path will call `set_inline_error(None)` so
    // the dialog dismisses the error before transitioning to
    // `Unlocked`.
    let mut state = UnlockDialogState::new();
    state.set_inline_error(Some(InlineError::from_error(&PaladinError::DecryptFailed)));
    state.set_inline_error(None);
    assert!(state.inline_error().is_none());
}

#[test]
fn unlock_dialog_state_set_passphrase_clears_prior_inline_error() {
    // After a `decrypt_failed` lands, the user re-types. The first
    // keystroke must dismiss the prior inline error so the entry
    // does not carry a stale "wrong passphrase" message into the
    // next attempt. This matches the standard GNOME unlock-surface
    // affordance.
    let mut state = UnlockDialogState::new();
    state.set_inline_error(Some(InlineError::from_error(&PaladinError::DecryptFailed)));
    assert!(state.inline_error().is_some());
    state.set_passphrase("h");
    assert!(
        state.inline_error().is_none(),
        "first keystroke after a decrypt_failed must dismiss the inline error",
    );
}

#[test]
fn unlock_dialog_state_clear_passphrase_also_clears_inline_error() {
    // `clear_passphrase` runs on cancel / auto-lock; both
    // transitions must leave a clean state so a re-mounted dialog
    // does not flash a stale `decrypt_failed`.
    let mut state = UnlockDialogState::new();
    state.set_passphrase("hunter2");
    state.set_inline_error(Some(InlineError::from_error(&PaladinError::DecryptFailed)));
    state.clear_passphrase();
    assert!(state.is_passphrase_empty());
    assert!(state.inline_error().is_none());
}

#[test]
fn unlock_dialog_state_take_passphrase_also_clears_inline_error() {
    // Submit consumes the passphrase bytes via `take_passphrase`; the
    // worker is about to run, so any stale inline error from a prior
    // attempt must clear before the result lands.
    let mut state = UnlockDialogState::new();
    state.set_passphrase("hunter2");
    state.set_inline_error(Some(InlineError::from_error(&PaladinError::DecryptFailed)));
    let _ = state.take_passphrase();
    assert!(state.is_passphrase_empty());
    assert!(
        state.inline_error().is_none(),
        "take_passphrase must clear the inline error so worker results land into clean state",
    );
}

// ---------------------------------------------------------------------------
// UnlockDialogState::submit — the pre-flight submit gate the widget's
// `connect_clicked` handler runs when the user clicks "Unlock". Empty
// passphrase short-circuits to `SubmitRejection::EmptyPassphrase` and
// stages the inline error so the user sees the rejection without
// spawning a worker. Non-empty submits build the
// `VaultLock::Encrypted` for the (deferred) `paladin_core::open`
// worker and consume the shadow buffer so the cleartext bytes do not
// outlive the submit.
// ---------------------------------------------------------------------------

#[test]
fn unlock_dialog_state_submit_empty_passphrase_returns_rejection() {
    // The "Unlock" button is sensitivity-gated on
    // `submit_button_sensitive()` so the empty case should not fire
    // through a click. Defense-in-depth: if a keyboard accelerator or
    // a reactive race ever bypasses the gate, `submit` must still
    // short-circuit to the stable §5 `invalid_passphrase`/`zero_length`
    // rejection rather than spawning a worker.
    let mut state = UnlockDialogState::new();
    let result = state.submit();
    match result {
        Err(SubmitRejection::EmptyPassphrase) => {}
        Ok(_) => panic!("expected EmptyPassphrase rejection, got Ok"),
    }
}

#[test]
fn unlock_dialog_state_submit_empty_passphrase_stages_inline_error() {
    // The rejection must surface inline beneath the passphrase entry
    // via the same projection the `gtk::Label` binding reads, so the
    // user sees a rendered message without re-routing through the
    // widget layer.
    let mut state = UnlockDialogState::new();
    let _ = state.submit();
    let inline = state
        .inline_error()
        .expect("submit on empty passphrase must stage an inline error");
    assert_eq!(inline.kind, ErrorKind::InvalidPassphrase);
    let expected = InlineError::from_rejection(SubmitRejection::EmptyPassphrase);
    assert_eq!(inline.rendered, expected.rendered);
}

#[test]
fn unlock_dialog_state_submit_empty_passphrase_overwrites_prior_inline_error() {
    // The user could have a stale `decrypt_failed` in the inline slot
    // (e.g. the worker landed it, the user did not type, and triggered
    // submit again via a keyboard shortcut). The new rejection must
    // replace the prior projection so the visible message reflects the
    // current cause.
    let mut state = UnlockDialogState::new();
    state.set_inline_error(Some(InlineError::from_error(&PaladinError::DecryptFailed)));
    let _ = state.submit();
    let inline = state
        .inline_error()
        .expect("submit on empty passphrase must stage an inline error");
    assert_eq!(inline.kind, ErrorKind::InvalidPassphrase);
}

#[test]
fn unlock_dialog_state_submit_non_empty_returns_encrypted_lock() {
    // The submit handler hands the returned `VaultLock` to the
    // (deferred) `gio::spawn_blocking paladin_core::open` worker.
    // Pin the variant so future widget wiring can match it without a
    // type assertion at the call site.
    let mut state = UnlockDialogState::new();
    state.set_passphrase("hunter2");
    let lock = state
        .submit()
        .expect("non-empty passphrase must build a VaultLock");
    match lock {
        VaultLock::Encrypted(_) => {}
        other => panic!("expected VaultLock::Encrypted, got {other:?}"),
    }
}

#[test]
fn unlock_dialog_state_submit_non_empty_consumes_passphrase_buffer() {
    // Cleartext bytes must not outlive the submit. The widget hands the
    // lock to the worker; the shadow buffer is wiped in the same step
    // so a subsequent screenshot / accessibility scrape cannot recover
    // the typed bytes.
    let mut state = UnlockDialogState::new();
    state.set_passphrase("hunter2");
    let _ = state.submit();
    assert!(
        state.is_passphrase_empty(),
        "submit must consume the buffer on the Ok path",
    );
}

#[test]
fn unlock_dialog_state_submit_non_empty_clears_prior_inline_error() {
    // A stale `decrypt_failed` from a prior worker return must not
    // outlive a successful re-submit. The worker result lands into
    // clean state.
    let mut state = UnlockDialogState::new();
    state.set_passphrase("hunter2");
    state.set_inline_error(Some(InlineError::from_error(&PaladinError::DecryptFailed)));
    let _ = state.submit();
    assert!(
        state.inline_error().is_none(),
        "submit on non-empty passphrase must clear the inline error",
    );
}

#[test]
fn unlock_dialog_state_submit_rejection_preserves_empty_buffer() {
    // Rejection short-circuits before any worker spawn; the buffer was
    // already empty, and `submit` must not mutate it into a non-empty
    // state (would defeat the sensitivity gate on the next render).
    let mut state = UnlockDialogState::new();
    let _ = state.submit();
    assert!(state.is_passphrase_empty());
}

// ---------------------------------------------------------------------------
// UnlockDialogMsg::SubmitClicked — emitted from the Unlock button's
// `connect_clicked` signal. The widget's `update` handler runs
// `UnlockDialogState::submit` so the rejection path stages the inline
// error and the Ok path will hand the `VaultLock` to the future
// `gio::spawn_blocking paladin_core::open` worker.
// ---------------------------------------------------------------------------

#[test]
fn unlock_dialog_msg_submit_clicked_pattern_matches() {
    // The variant carries no payload — `connect_clicked` fires on a
    // raw click with no parameters. Pin the unit shape so a future
    // refactor that adds a payload trips this test.
    let msg = UnlockDialogMsg::SubmitClicked;
    match msg {
        UnlockDialogMsg::SubmitClicked => {}
        UnlockDialogMsg::PassphraseChanged(_) => {
            panic!("expected SubmitClicked, got PassphraseChanged")
        }
    }
}

// ---------------------------------------------------------------------------
// apply_msg — routing decisions
//
// The pure-logic shim wraps `UnlockDialogState::set_passphrase` and
// `UnlockDialogState::submit` so the widget's `update` handler stays
// a one-liner over a unit-testable router. `PassphraseChanged`
// mutates the shadow buffer and emits no output. `SubmitClicked`
// runs `submit`: rejection stages the inline error and emits no
// output; the `Ok(VaultLock)` branch is forwarded to `AppModel` as
// `UnlockDialogOutput::SubmitLock` so the future
// `gio::spawn_blocking paladin_core::open` worker can consume it.
// ---------------------------------------------------------------------------

#[test]
fn apply_msg_passphrase_changed_updates_buffer_and_emits_no_output() {
    let mut state = UnlockDialogState::new();
    let out = apply_msg(
        &mut state,
        UnlockDialogMsg::PassphraseChanged("hunter2".to_string()),
    );
    assert!(
        out.is_none(),
        "PassphraseChanged must not emit an output — it only shadows the typed bytes",
    );
    assert_eq!(state.passphrase_text(), "hunter2");
}

#[test]
fn apply_msg_passphrase_changed_to_empty_reports_empty() {
    let mut state = UnlockDialogState::new();
    state.set_passphrase("hunter2");
    let out = apply_msg(
        &mut state,
        UnlockDialogMsg::PassphraseChanged(String::new()),
    );
    assert!(out.is_none());
    assert!(
        state.is_passphrase_empty(),
        "PassphraseChanged with empty text must clear the buffer so the gate re-closes",
    );
}

#[test]
fn apply_msg_passphrase_changed_clears_prior_inline_error() {
    // A `decrypt_failed` from a prior worker return must be dismissed
    // the moment the user keeps typing — the dismissal contract that
    // `set_passphrase` enforces must survive the `apply_msg` shim.
    let mut state = UnlockDialogState::new();
    state.set_inline_error(Some(InlineError::from_error(&PaladinError::DecryptFailed)));
    let _ = apply_msg(
        &mut state,
        UnlockDialogMsg::PassphraseChanged("h".to_string()),
    );
    assert!(state.inline_error().is_none());
}

#[test]
fn apply_msg_submit_clicked_empty_returns_none() {
    // Empty passphrase short-circuits inside `submit`. No `VaultLock`
    // ever materializes, so no output is forwarded to `AppModel`.
    let mut state = UnlockDialogState::new();
    let out = apply_msg(&mut state, UnlockDialogMsg::SubmitClicked);
    assert!(
        out.is_none(),
        "SubmitClicked on an empty buffer must not forward an output",
    );
}

#[test]
fn apply_msg_submit_clicked_empty_stages_inline_error() {
    // Mirrors the state-level `submit_empty_passphrase_stages_inline_error`
    // test: the rejection projection is staged into the inline-error slot
    // even when routed through `apply_msg`.
    let mut state = UnlockDialogState::new();
    let _ = apply_msg(&mut state, UnlockDialogMsg::SubmitClicked);
    let err = state
        .inline_error()
        .expect("rejection must stage an inline error");
    assert_eq!(err.kind, ErrorKind::InvalidPassphrase);
}

#[test]
fn apply_msg_submit_clicked_non_empty_returns_submit_lock() {
    let mut state = UnlockDialogState::new();
    state.set_passphrase("hunter2");
    let out = apply_msg(&mut state, UnlockDialogMsg::SubmitClicked);
    let output = out.expect("non-empty submit must forward a VaultLock");
    match output {
        UnlockDialogOutput::SubmitLock(lock) => match lock {
            VaultLock::Encrypted(_) => {}
            other => panic!("expected VaultLock::Encrypted, got {other:?}"),
        },
    }
}

#[test]
fn apply_msg_submit_clicked_non_empty_consumes_passphrase_buffer() {
    // Cleartext bytes must not outlive the submit. The widget hands
    // the lock to the worker; the shadow buffer is wiped in the same
    // step so a subsequent screenshot / accessibility scrape cannot
    // recover the typed bytes.
    let mut state = UnlockDialogState::new();
    state.set_passphrase("hunter2");
    let _ = apply_msg(&mut state, UnlockDialogMsg::SubmitClicked);
    assert!(
        state.is_passphrase_empty(),
        "apply_msg(SubmitClicked) on the Ok path must consume the buffer",
    );
}

#[test]
fn apply_msg_submit_clicked_non_empty_clears_prior_inline_error() {
    // A stale `decrypt_failed` from a prior worker return must not
    // outlive a successful re-submit routed through `apply_msg`.
    let mut state = UnlockDialogState::new();
    state.set_passphrase("hunter2");
    state.set_inline_error(Some(InlineError::from_error(&PaladinError::DecryptFailed)));
    let _ = apply_msg(&mut state, UnlockDialogMsg::SubmitClicked);
    assert!(state.inline_error().is_none());
}

#[test]
fn unlock_dialog_output_submit_lock_carries_encrypted_variant() {
    // `UnlockDialogOutput::SubmitLock` must wrap the `VaultLock` so
    // `AppModel` can pattern-match on the variant when the future
    // `gio::spawn_blocking paladin_core::open` worker is wired up.
    let mut state = UnlockDialogState::new();
    state.set_passphrase("hunter2");
    let out = apply_msg(&mut state, UnlockDialogMsg::SubmitClicked)
        .expect("non-empty submit must forward");
    let UnlockDialogOutput::SubmitLock(lock) = out;
    assert!(
        matches!(lock, VaultLock::Encrypted(_)),
        "SubmitLock must carry the encrypted lock built from the typed passphrase",
    );
}

// `format_unlock_dialog_marker` / `UNLOCK_DIALOG_MARKER_PREFIX` pin
// the `--exit-after-startup` stdout contract consumed by
// `tests/gtk_smoke.rs` for the `Locked` branch. Pure-logic tests
// live here so the contract is verified without spinning up a
// display server.

#[test]
fn unlock_dialog_marker_prefix_is_stable() {
    assert_eq!(
        paladin_gtk::unlock_dialog::UNLOCK_DIALOG_MARKER_PREFIX,
        "paladin-gtk: unlock_dialog_path=",
    );
}

#[test]
fn format_unlock_dialog_marker_renders_resolved_path() {
    let path = Path::new("/tmp/example/vault.bin");
    assert_eq!(
        paladin_gtk::unlock_dialog::format_unlock_dialog_marker(path),
        "paladin-gtk: unlock_dialog_path=/tmp/example/vault.bin",
    );
}

#[test]
fn format_unlock_dialog_marker_starts_with_prefix() {
    // Every rendered marker begins with `UNLOCK_DIALOG_MARKER_PREFIX`
    // so the smoke test can grep by prefix when the path varies.
    let marker = paladin_gtk::unlock_dialog::format_unlock_dialog_marker(Path::new("/x"));
    assert!(marker.starts_with(paladin_gtk::unlock_dialog::UNLOCK_DIALOG_MARKER_PREFIX));
}
