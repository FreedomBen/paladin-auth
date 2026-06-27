// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic secret-field tests for `paladin-auth-gtk`.
//!
//! Tracks the §"Tests > Pure-logic unit tests > `tests/secret_fields_logic.rs`"
//! checklist in `docs/IMPLEMENTATION_PLAN_04_GTK.md`:
//!
//! * Secret-field clearing / redaction invariants for passphrase,
//!   manual-secret, and `otpauth://` URI entry buffers (submit,
//!   cancel, close, auto-lock).
//! * Add path-switch clears the hidden Base32 manual secret, the URI
//!   text, and any pending duplicate-add state before the new path
//!   becomes active.
//! * Pending `ValidatedAccount` (Add duplicate-collision) and pending
//!   `VaultInit` (Init `vault_exists` race) are zeroized on cancel,
//!   close, replacement, and auto-lock.
//!
//! The module under test (`paladin_auth_gtk::secret_fields`) models the
//! state machine the GTK / libadwaita widgets shadow. Wrapping the
//! GTK entry buffers (`gtk::EntryBuffer`) is the unavoidable UI
//! boundary; this pure-logic layer owns the
//! `secrecy::SecretString` / `Zeroizing<String>` copies and the
//! Paladin Auth-owned `Box<ValidatedAccount>` / `VaultInit` pending slots
//! that DESIGN §8 and the plan's §"Secret entry handling" pin down.

use std::time::SystemTime;

use secrecy::SecretString;
use zeroize::Zeroizing;

use paladin_auth_core::{
    validate_manual, AccountInput, AccountKindInput, Algorithm, EncryptionOptions, IconHintInput,
    ValidatedAccount, VaultInit, DIGITS_DEFAULT, TOTP_PERIOD_DEFAULT,
};

use paladin_auth_gtk::secret_fields::{
    AddPath, AddSecretState, ClearReason, InitSecretState, SecretEntry,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const BASE32_SECRET: &str = "JBSWY3DPEHPK3PXP"; // RFC 4648 sample ("Hello!\xDE\xAD\xBE\xEF")

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000)
}

fn sample_validated(label: &str) -> ValidatedAccount {
    let input = AccountInput {
        label: label.to_string(),
        issuer: Some("Example".to_string()),
        secret: SecretString::from(BASE32_SECRET.to_string()),
        algorithm: Algorithm::Sha1,
        digits: DIGITS_DEFAULT,
        kind: AccountKindInput::Totp,
        period_secs: Some(TOTP_PERIOD_DEFAULT),
        counter: None,
        icon_hint: IconHintInput::Default,
    };
    validate_manual(input, now()).expect("test fixture validates")
}

fn encrypted_init(passphrase: &str) -> VaultInit {
    let opts = EncryptionOptions::new(SecretString::from(passphrase.to_string()))
        .expect("non-empty passphrase accepted");
    VaultInit::Encrypted(opts)
}

// ---------------------------------------------------------------------------
// SecretEntry covers the passphrase / manual-secret / URI buffer slot
// ---------------------------------------------------------------------------

#[test]
fn secret_entry_starts_empty() {
    let buf = SecretEntry::new();
    assert!(buf.is_empty());
    assert_eq!(buf.text(), "");
}

#[test]
fn secret_entry_set_text_then_clear() {
    let mut buf = SecretEntry::new();
    buf.set("hunter2");
    assert_eq!(buf.text(), "hunter2");
    assert!(!buf.is_empty());
    buf.clear();
    assert_eq!(buf.text(), "");
    assert!(buf.is_empty());
}

#[test]
fn secret_entry_take_returns_zeroizing_and_empties_self() {
    // `take` returns the stored value wrapped in `Zeroizing<String>`
    // so the caller can hand it to `SecretString::from(...)` and let
    // it drop after the core call, zeroizing the bytes. The source
    // buffer is left empty so subsequent reads cannot leak the
    // previous value.
    let mut buf = SecretEntry::from("hunter2");
    let taken: Zeroizing<String> = buf.take();
    assert_eq!(taken.as_str(), "hunter2");
    assert!(buf.is_empty(), "take must empty the source");
    assert_eq!(buf.text(), "");
    // `Zeroizing<String>` derefs to `&String`; reading via `.as_str()`
    // exercises the wrapper API and confirms the type is in place.
    drop(taken);
}

#[test]
fn secret_entry_drop_zeroizes_inner_bytes_structurally() {
    // Structural: the inner buffer must be `Zeroizing<String>` so
    // dropping the `SecretEntry` zeroes the bytes. Verify by
    // round-tripping through `take()` which returns the wrapper
    // type — a bare `String` would not satisfy the type signature
    // the module exposes.
    let mut buf = SecretEntry::from("super-secret");
    let snapshot: String = buf.text().to_string();
    let wiped: Zeroizing<String> = buf.take();
    assert_eq!(wiped.as_str(), snapshot.as_str());
    drop(wiped);
    // `buf` is left empty after `take`; subsequent reads must not
    // recover the previous value.
    assert!(buf.is_empty());
}

#[test]
fn secret_entry_clear_reasons_all_empty_the_buffer() {
    // The reason enum is informational for the caller; every Submit /
    // Cancel / Close / AutoLock invocation flows through `clear()`,
    // which empties the buffer regardless of `reason`.
    for reason in [
        ClearReason::Submit,
        ClearReason::Cancel,
        ClearReason::Close,
        ClearReason::AutoLock,
    ] {
        let mut buf = SecretEntry::from("hunter2");
        buf.clear();
        assert!(buf.is_empty(), "clear() must empty after {reason:?}");
    }
}

// ---------------------------------------------------------------------------
// Add path-switch clears the hidden buffer + pending duplicate-add
// ---------------------------------------------------------------------------

#[test]
fn add_state_starts_on_manual_path_with_empty_buffers_and_no_pending() {
    let s = AddSecretState::new();
    assert_eq!(s.active_path, AddPath::Manual);
    assert!(s.manual_secret.is_empty());
    assert!(s.uri_text.is_empty());
    assert!(s.pending.is_none());
}

#[test]
fn add_state_switch_manual_to_uri_clears_hidden_manual_secret() {
    let mut s = AddSecretState::new();
    s.manual_secret.set(BASE32_SECRET);
    s.uri_text
        .set("otpauth://totp/Example:bob@example.com?secret=ABC&issuer=Example");
    let prior = s.switch_path(AddPath::Uri);
    assert!(prior.is_none(), "no pending was set");
    assert_eq!(s.active_path, AddPath::Uri);
    assert!(
        s.manual_secret.is_empty(),
        "leaving Manual must wipe the hidden Base32 buffer"
    );
    assert!(
        !s.uri_text.is_empty(),
        "URI buffer (now active) is preserved across switch_path"
    );
}

#[test]
fn add_state_switch_uri_to_manual_clears_hidden_uri_text() {
    let mut s = AddSecretState::new();
    s.switch_path(AddPath::Uri); // start on Uri
    s.uri_text
        .set("otpauth://totp/Example:bob@example.com?secret=ABC&issuer=Example");
    s.manual_secret.set(BASE32_SECRET);
    let prior = s.switch_path(AddPath::Manual);
    assert!(prior.is_none());
    assert_eq!(s.active_path, AddPath::Manual);
    assert!(
        s.uri_text.is_empty(),
        "leaving Uri must wipe the hidden URI buffer"
    );
    assert!(
        !s.manual_secret.is_empty(),
        "manual buffer (now active) is preserved across switch_path"
    );
}

#[test]
fn add_state_switch_same_path_is_noop() {
    let mut s = AddSecretState::new();
    s.manual_secret.set(BASE32_SECRET);
    let pending_before = s.replace_pending(sample_validated("acct"));
    assert!(pending_before.is_none());
    let prior = s.switch_path(AddPath::Manual);
    assert!(
        prior.is_none(),
        "idempotent same-path switch returns no prior"
    );
    assert_eq!(s.manual_secret.text(), BASE32_SECRET, "no buffer mutation");
    assert!(
        s.pending.is_some(),
        "idempotent same-path switch must not drop pending"
    );
}

#[test]
fn add_state_path_switch_drops_pending_duplicate_add() {
    let mut s = AddSecretState::new();
    s.manual_secret.set(BASE32_SECRET);
    let _ = s.replace_pending(sample_validated("acct"));
    let prior = s.switch_path(AddPath::Uri);
    assert!(
        prior.is_some(),
        "switch_path returns the prior pending so caller drops it"
    );
    assert!(
        s.pending.is_none(),
        "pending duplicate-add slot must be cleared on path switch"
    );
    // Dropping `prior` here zeroizes the carried `Secret` via the
    // `ZeroizeOnDrop` impl on `paladin_auth_core::Secret`.
    drop(prior);
}

#[test]
fn add_state_switch_manual_to_qr_clears_hidden_manual_secret() {
    // Switching from Manual to the clipboard-QR page wipes the
    // hidden Base32 buffer for the leaving Manual path, matching
    // the Manual→Uri contract. The QR page has no secret-bearing
    // buffer of its own (it activates against a fresh clipboard
    // texture read), so there is nothing to preserve on the
    // arriving side.
    let mut s = AddSecretState::new();
    s.manual_secret.set(BASE32_SECRET);
    let prior = s.switch_path(AddPath::Qr);
    assert!(prior.is_none(), "no pending was set");
    assert_eq!(s.active_path, AddPath::Qr);
    assert!(
        s.manual_secret.is_empty(),
        "leaving Manual must wipe the hidden Base32 buffer when arriving on Qr"
    );
}

#[test]
fn add_state_switch_uri_to_qr_clears_hidden_uri_text() {
    // Switching from Uri to the clipboard-QR page wipes the hidden
    // URI buffer for the leaving Uri path, matching the Uri→Manual
    // contract. The QR page has no secret-bearing buffer of its
    // own.
    let mut s = AddSecretState::new();
    s.switch_path(AddPath::Uri);
    s.uri_text
        .set("otpauth://totp/Example:bob@example.com?secret=ABC&issuer=Example");
    let prior = s.switch_path(AddPath::Qr);
    assert!(prior.is_none(), "no pending was set");
    assert_eq!(s.active_path, AddPath::Qr);
    assert!(
        s.uri_text.is_empty(),
        "leaving Uri must wipe the hidden URI buffer when arriving on Qr"
    );
}

#[test]
fn add_state_switch_qr_to_manual_preserves_manual_buffer() {
    // Returning from the clipboard-QR page to Manual leaves the
    // Manual buffer untouched because the QR page does not own a
    // secret-bearing buffer to wipe on departure. Pinning this
    // keeps a future `switch_path` change from accidentally
    // erasing typed input on the arriving Manual page.
    let mut s = AddSecretState::new();
    s.manual_secret.set(BASE32_SECRET);
    s.switch_path(AddPath::Qr);
    assert!(
        s.manual_secret.is_empty(),
        "precondition: Manual→Qr wiped the Manual buffer"
    );
    // Re-populate Manual before switching back so the test
    // verifies the return-to-Manual path preserves what the user
    // re-typed on the QR page's hidden adjacent state.
    s.manual_secret.set(BASE32_SECRET);
    let prior = s.switch_path(AddPath::Manual);
    assert!(prior.is_none(), "no pending was set");
    assert_eq!(s.active_path, AddPath::Manual);
    assert_eq!(
        s.manual_secret.text(),
        BASE32_SECRET,
        "Qr→Manual must preserve the Manual buffer because Qr owns no buffer to wipe",
    );
}

#[test]
fn add_state_switch_qr_to_uri_preserves_uri_buffer() {
    // Mirror of `add_state_switch_qr_to_manual_preserves_manual_buffer`
    // on the URI side: the QR page owns no leaving buffer, so a
    // Qr→Uri switch must keep the URI buffer intact.
    let mut s = AddSecretState::new();
    s.switch_path(AddPath::Qr);
    s.uri_text
        .set("otpauth://totp/Example:bob@example.com?secret=ABC&issuer=Example");
    let prior = s.switch_path(AddPath::Uri);
    assert!(prior.is_none(), "no pending was set");
    assert_eq!(s.active_path, AddPath::Uri);
    assert_eq!(
        s.uri_text.text(),
        "otpauth://totp/Example:bob@example.com?secret=ABC&issuer=Example",
        "Qr→Uri must preserve the URI buffer because Qr owns no buffer to wipe",
    );
}

#[test]
fn add_state_switch_same_qr_is_noop() {
    // Idempotent same-path switch on the QR page mirrors
    // `add_state_switch_same_path_is_noop` for Manual: pending
    // duplicate-add state survives the re-entry so the alert dialog
    // re-presented on a redundant SwitchPath dispatch keeps its
    // staged validated account.
    let mut s = AddSecretState::new();
    s.switch_path(AddPath::Qr);
    let pending_before = s.replace_pending(sample_validated("acct"));
    assert!(pending_before.is_none());
    let prior = s.switch_path(AddPath::Qr);
    assert!(
        prior.is_none(),
        "idempotent same-path switch on Qr returns no prior"
    );
    assert!(
        s.pending.is_some(),
        "idempotent same-path switch on Qr must not drop pending"
    );
}

#[test]
fn add_state_path_switch_to_qr_drops_pending_duplicate_add() {
    // A path switch into the QR page drops any pending
    // duplicate-add state, mirroring the Manual→Uri contract. The
    // caller receives the prior `Box<ValidatedAccount>` so the
    // `ZeroizeOnDrop` impl on `paladin_auth_core::Secret` wipes the
    // staged secret when the return drops.
    let mut s = AddSecretState::new();
    s.manual_secret.set(BASE32_SECRET);
    let _ = s.replace_pending(sample_validated("acct"));
    let prior = s.switch_path(AddPath::Qr);
    assert!(
        prior.is_some(),
        "switch_path returns the prior pending so caller drops it"
    );
    assert!(
        s.pending.is_none(),
        "pending duplicate-add slot must be cleared on Manual→Qr switch"
    );
    drop(prior);
}

// ---------------------------------------------------------------------------
// Pending ValidatedAccount zeroized on cancel / close / replacement / auto-lock
// ---------------------------------------------------------------------------

#[test]
fn add_state_replace_pending_returns_prior() {
    let mut s = AddSecretState::new();
    assert!(s.replace_pending(sample_validated("first")).is_none());
    let prior = s
        .replace_pending(sample_validated("second"))
        .expect("prior returned on replacement");
    assert_eq!(
        prior.account.label(),
        "first",
        "prior returned for caller to drop"
    );
    assert!(s.pending.is_some(), "new pending installed");
    drop(prior);
}

#[test]
fn add_state_clear_for_cancel_drops_pending_and_buffers() {
    let mut s = AddSecretState::new();
    s.manual_secret.set(BASE32_SECRET);
    let _ = s.replace_pending(sample_validated("acct"));
    let prior = s.clear_for(ClearReason::Cancel);
    assert!(prior.is_some());
    assert!(s.pending.is_none());
    assert!(s.manual_secret.is_empty());
    assert!(s.uri_text.is_empty());
}

#[test]
fn add_state_clear_for_close_drops_pending_and_buffers() {
    let mut s = AddSecretState::new();
    s.manual_secret.set(BASE32_SECRET);
    let _ = s.replace_pending(sample_validated("acct"));
    let prior = s.clear_for(ClearReason::Close);
    assert!(prior.is_some());
    assert!(s.pending.is_none());
    assert!(s.manual_secret.is_empty());
}

#[test]
fn add_state_clear_for_auto_lock_drops_pending_and_buffers() {
    let mut s = AddSecretState::new();
    s.uri_text
        .set("otpauth://totp/Example:bob@example.com?secret=ABC&issuer=Example");
    let _ = s.replace_pending(sample_validated("acct"));
    let prior = s.clear_for(ClearReason::AutoLock);
    assert!(prior.is_some());
    assert!(s.pending.is_none());
    assert!(s.uri_text.is_empty());
}

#[test]
fn add_state_clear_for_submit_drops_pending_and_buffers() {
    // Submit also has to wipe both buffers and any leftover pending
    // slot — DESIGN §8's submit/cancel/close/auto-lock invariant.
    let mut s = AddSecretState::new();
    s.manual_secret.set(BASE32_SECRET);
    let _ = s.replace_pending(sample_validated("acct"));
    let prior = s.clear_for(ClearReason::Submit);
    assert!(prior.is_some());
    assert!(s.pending.is_none());
    assert!(s.manual_secret.is_empty());
    assert!(s.uri_text.is_empty());
}

#[test]
fn add_state_consume_pending_returns_then_clears_buffers() {
    // The "add anyway" confirmation consumes the pending validated
    // account and continues with the vault submission; both buffers
    // are wiped before the worker spawns.
    let mut s = AddSecretState::new();
    s.manual_secret.set(BASE32_SECRET);
    let _ = s.replace_pending(sample_validated("acct"));
    let taken = s.consume_pending().expect("pending taken");
    assert_eq!(taken.account.label(), "acct");
    assert!(s.pending.is_none());
    assert!(s.manual_secret.is_empty());
    assert!(s.uri_text.is_empty());
    drop(taken);
}

// ---------------------------------------------------------------------------
// InitSecretState — pending VaultInit zeroized on the same triggers
// ---------------------------------------------------------------------------

#[test]
fn init_state_starts_with_empty_passphrase_fields_and_no_pending() {
    let s = InitSecretState::new();
    assert!(s.passphrase.is_empty());
    assert!(s.confirm.is_empty());
    assert!(s.pending.is_none());
}

#[test]
fn init_state_replace_pending_returns_prior_vault_init() {
    let mut s = InitSecretState::new();
    assert!(s.replace_pending(VaultInit::Plaintext).is_none());
    let prior = s
        .replace_pending(encrypted_init("hunter2"))
        .expect("prior returned on replacement");
    assert!(matches!(prior, VaultInit::Plaintext));
    assert!(s.pending.is_some());
    drop(prior);
}

#[test]
fn init_state_clear_for_cancel_drops_pending_and_buffers() {
    let mut s = InitSecretState::new();
    s.passphrase.set("hunter2");
    s.confirm.set("hunter2");
    let _ = s.replace_pending(encrypted_init("hunter2"));
    let prior = s.clear_for(ClearReason::Cancel);
    assert!(prior.is_some());
    assert!(s.pending.is_none());
    assert!(s.passphrase.is_empty());
    assert!(s.confirm.is_empty());
}

#[test]
fn init_state_clear_for_close_drops_pending_and_buffers() {
    let mut s = InitSecretState::new();
    s.passphrase.set("hunter2");
    s.confirm.set("hunter2");
    let _ = s.replace_pending(encrypted_init("hunter2"));
    let prior = s.clear_for(ClearReason::Close);
    assert!(prior.is_some());
    assert!(s.pending.is_none());
    assert!(s.passphrase.is_empty());
    assert!(s.confirm.is_empty());
}

#[test]
fn init_state_clear_for_auto_lock_drops_pending_and_buffers() {
    // Auto-lock can fire only on an unlocked encrypted vault, which
    // implies the Init dialog is not on screen — but the contract is
    // defensive: if an auto-lock signal reaches the Init component
    // (e.g. via a global handler) it must wipe pending state and
    // both passphrase fields.
    let mut s = InitSecretState::new();
    s.passphrase.set("hunter2");
    s.confirm.set("hunter2");
    let _ = s.replace_pending(encrypted_init("hunter2"));
    let prior = s.clear_for(ClearReason::AutoLock);
    assert!(prior.is_some());
    assert!(s.pending.is_none());
    assert!(s.passphrase.is_empty());
    assert!(s.confirm.is_empty());
}

#[test]
fn init_state_clear_for_submit_drops_pending_and_buffers() {
    let mut s = InitSecretState::new();
    s.passphrase.set("hunter2");
    s.confirm.set("hunter2");
    let _ = s.replace_pending(encrypted_init("hunter2"));
    let prior = s.clear_for(ClearReason::Submit);
    assert!(prior.is_some());
    assert!(s.pending.is_none());
    assert!(s.passphrase.is_empty());
    assert!(s.confirm.is_empty());
}

#[test]
fn init_state_consume_pending_returns_then_clears_buffers() {
    let mut s = InitSecretState::new();
    s.passphrase.set("hunter2");
    s.confirm.set("hunter2");
    let _ = s.replace_pending(encrypted_init("hunter2"));
    let taken = s.consume_pending().expect("pending taken");
    assert!(matches!(taken, VaultInit::Encrypted(_)));
    assert!(s.pending.is_none());
    assert!(s.passphrase.is_empty());
    assert!(s.confirm.is_empty());
    drop(taken);
}

// ---------------------------------------------------------------------------
// Defensive: `replace_pending` zeroizes the prior on drop
// ---------------------------------------------------------------------------

#[test]
fn add_state_replace_pending_drops_prior_when_caller_discards_return() {
    // The reducer can discard the return of `replace_pending` via
    // `let _ = ...`. The compiler still drops the returned
    // `Box<ValidatedAccount>` at the end of the let-binding, which
    // wipes the `Secret` bytes via its `ZeroizeOnDrop` impl. This
    // test asserts the function returns the prior so callers always
    // have the opportunity to discard via Drop.
    let mut s = AddSecretState::new();
    let _ = s.replace_pending(sample_validated("first"));
    let prior = s.replace_pending(sample_validated("second"));
    assert!(prior.is_some());
}

#[test]
fn init_state_replace_pending_drops_prior_when_caller_discards_return() {
    let mut s = InitSecretState::new();
    let _ = s.replace_pending(VaultInit::Plaintext);
    let prior = s.replace_pending(encrypted_init("hunter2"));
    assert!(prior.is_some());
}
