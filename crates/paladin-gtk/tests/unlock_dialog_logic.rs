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

use paladin_core::{ErrorKind, PaladinError, PermissionSubject, VaultLock, VaultMode, VaultStatus};

use paladin_gtk::secret_fields::SecretEntry;
use paladin_gtk::startup_error::{OpenErrorRouting, StartupErrorSource};
use paladin_gtk::unlock_dialog::{
    classify_unlock_error, prepare_unlock_lock, unlock_view_required, SubmitRejection,
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
