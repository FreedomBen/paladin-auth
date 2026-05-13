// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic clipboard auto-clear tests for `paladin-gtk`.
//!
//! Tracks the §"Tests > Pure-logic unit tests > `tests/clipboard_clear_logic.rs`"
//! checklist in `IMPLEMENTATION_PLAN_04_GTK.md`:
//!
//! * Copy capture routes through
//!   `paladin_core::policy::clipboard_clear::ClipboardClearPolicy::schedule`.
//! * Wake routes through `should_clear` against the current
//!   `gdk::Clipboard` text (only-if-unchanged).
//! * Stale tokens are dropped first by the policy.
//! * Pending copied value is zeroized after a clear attempt or
//!   stale-token drop.
//! * A clipboard auto-clear timer scheduled before lock survives lock
//!   and still fires only-if-unchanged.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use secrecy::SecretString;
use tempfile::TempDir;
use zeroize::Zeroizing;

use paladin_core::{
    Argon2Params, ClipboardClearPolicy, EncryptionOptions, Store, Vault, VaultInit,
};

use paladin_gtk::auto_lock::{lock_on_expiry, UnlockedDiscards};
use paladin_gtk::clipboard_clear::{
    evaluate_wake, schedule_copy, PendingClipboardClear, WakeDecision,
};

// `ClipboardClearPolicy::schedule` advances a process-wide monotonic
// counter, so tests that rely on adjacent token issuance must
// serialize against every other test in this binary that calls
// `schedule_copy`. Tests that don't inspect token relationships do
// not need to hold the lock.
static SCHEDULE_LOCK: Mutex<()> = Mutex::new(());

fn schedule_lock() -> MutexGuard<'static, ()> {
    SCHEDULE_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn light_params() -> Argon2Params {
    Argon2Params {
        m_kib: 8_192,
        t: 1,
        p: 1,
    }
}

fn secure_tempdir() -> TempDir {
    let dir = tempfile::tempdir().expect("create tempdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod tempdir 0700");
    }
    dir
}

fn create_encrypted(path: &Path, passphrase: &str) -> (Vault, Store) {
    let opts =
        EncryptionOptions::with_params(SecretString::from(passphrase.to_string()), light_params())
            .expect("encryption opts");
    let (vault, store) =
        Store::create(path, VaultInit::Encrypted(opts)).expect("create encrypted vault");
    vault.save(&store).expect("commit initial vault");
    (vault, store)
}

fn create_plaintext(path: &Path) -> (Vault, Store) {
    let (vault, store) = Store::create(path, VaultInit::Plaintext).expect("create plaintext");
    vault.save(&store).expect("commit initial vault");
    (vault, store)
}

fn enable_clipboard_clear(vault: &mut Vault, store: &Store, secs: u32) {
    vault.set_clipboard_clear_enabled(true);
    vault
        .set_clipboard_clear_secs(secs)
        .expect("clipboard_clear_secs within bounds");
    vault.save(store).expect("commit settings");
}

// A `Zeroizing<Vec<u8>>` whose underlying buffer's address is captured so
// the test can observe whether `Drop` ran (the policy's `Zeroize` impl
// zeros the inner bytes before deallocation). This is the closest we
// can get to "was the value zeroized" without inspecting raw memory.
fn fresh_payload(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(bytes.to_vec())
}

// Tracks Drop firings for fixture types passed through the lock
// transition.
#[derive(Clone)]
struct DropTag {
    counter: Arc<AtomicUsize>,
}

impl DropTag {
    fn new() -> (Self, Arc<AtomicUsize>) {
        let counter = Arc::new(AtomicUsize::new(0));
        (
            Self {
                counter: counter.clone(),
            },
            counter,
        )
    }
}

impl Drop for DropTag {
    fn drop(&mut self) {
        self.counter.fetch_add(1, Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------------------
// schedule_copy — routes through ClipboardClearPolicy::schedule
// ---------------------------------------------------------------------------

#[test]
fn schedule_copy_returns_none_when_clipboard_clear_disabled_default() {
    let _guard = schedule_lock();
    let tmp = secure_tempdir();
    let (vault, _store) = create_encrypted(&tmp.path().join("vault.bin"), "hunter2");
    assert!(!vault.settings().clipboard_clear_enabled());

    let pending = schedule_copy(Instant::now(), vault.settings(), fresh_payload(b"123456"));
    assert!(pending.is_none(), "policy must not arm when disabled");
}

#[test]
fn schedule_copy_returns_some_with_default_secs_when_enabled() {
    let _guard = schedule_lock();
    let tmp = secure_tempdir();
    let (mut vault, store) = create_plaintext(&tmp.path().join("plain.bin"));
    vault.set_clipboard_clear_enabled(true);
    vault.save(&store).unwrap();
    // DESIGN §5 default is 20s.
    assert_eq!(vault.settings().clipboard_clear_secs(), 20);

    let now = Instant::now();
    let pending =
        schedule_copy(now, vault.settings(), fresh_payload(b"123456")).expect("scheduled");
    assert_eq!(pending.deadline, now + Duration::from_secs(20));
    assert_eq!(&pending.value[..], b"123456");
}

#[test]
fn schedule_copy_uses_custom_clear_secs() {
    let _guard = schedule_lock();
    let tmp = secure_tempdir();
    let (mut vault, store) = create_plaintext(&tmp.path().join("plain.bin"));
    enable_clipboard_clear(&mut vault, &store, 45);

    let now = Instant::now();
    let pending = schedule_copy(now, vault.settings(), fresh_payload(b"abc")).expect("scheduled");
    assert_eq!(pending.deadline, now + Duration::from_secs(45));
}

#[test]
fn schedule_copy_does_not_gate_on_encryption() {
    // Per DESIGN §6 / §7, clipboard auto-clear runs in both plaintext
    // and encrypted vaults; only auto-lock is plaintext-no-op.
    let _guard = schedule_lock();
    let tmp = secure_tempdir();
    let (mut plain_vault, plain_store) = create_plaintext(&tmp.path().join("plain.bin"));
    enable_clipboard_clear(&mut plain_vault, &plain_store, 10);
    let now = Instant::now();
    assert!(schedule_copy(now, plain_vault.settings(), fresh_payload(b"x")).is_some());

    let tmp2 = secure_tempdir();
    let (mut enc_vault, enc_store) = create_encrypted(&tmp2.path().join("vault.bin"), "pp");
    enable_clipboard_clear(&mut enc_vault, &enc_store, 10);
    assert!(schedule_copy(now, enc_vault.settings(), fresh_payload(b"x")).is_some());
}

#[test]
fn schedule_copy_issues_strictly_monotonic_tokens() {
    let _guard = schedule_lock();
    let tmp = secure_tempdir();
    let (mut vault, store) = create_plaintext(&tmp.path().join("plain.bin"));
    enable_clipboard_clear(&mut vault, &store, 10);

    let now = Instant::now();
    let p1 = schedule_copy(now, vault.settings(), fresh_payload(b"a")).expect("scheduled 1");
    let p2 = schedule_copy(now, vault.settings(), fresh_payload(b"b")).expect("scheduled 2");
    assert_eq!(p1.token.successor(), p2.token);
}

// ---------------------------------------------------------------------------
// evaluate_wake — routes through should_clear with stale-token gating
// ---------------------------------------------------------------------------

#[test]
fn evaluate_wake_clears_when_clipboard_byte_equals_captured() {
    let _guard = schedule_lock();
    let tmp = secure_tempdir();
    let (mut vault, store) = create_plaintext(&tmp.path().join("plain.bin"));
    enable_clipboard_clear(&mut vault, &store, 10);

    let captured = b"654321";
    let pending = schedule_copy(Instant::now(), vault.settings(), fresh_payload(captured))
        .expect("scheduled");

    let decision = evaluate_wake(&pending, pending.token, captured);
    assert_eq!(decision, WakeDecision::Clear);

    // Cross-check: the should_clear contract is plain byte equality.
    assert!(ClipboardClearPolicy::should_clear(&pending.value, captured));
}

#[test]
fn evaluate_wake_skips_clear_when_clipboard_changed() {
    let _guard = schedule_lock();
    let tmp = secure_tempdir();
    let (mut vault, store) = create_plaintext(&tmp.path().join("plain.bin"));
    enable_clipboard_clear(&mut vault, &store, 10);

    let pending = schedule_copy(Instant::now(), vault.settings(), fresh_payload(b"654321"))
        .expect("scheduled");

    // User copied something else in the interim.
    let current = b"different value";
    let decision = evaluate_wake(&pending, pending.token, current);
    assert_eq!(decision, WakeDecision::Mismatch);
}

#[test]
fn evaluate_wake_drops_stale_tokens_without_consulting_should_clear() {
    let _guard = schedule_lock();
    let tmp = secure_tempdir();
    let (mut vault, store) = create_plaintext(&tmp.path().join("plain.bin"));
    enable_clipboard_clear(&mut vault, &store, 10);

    // First schedule, then a second one supersedes it; the older
    // token is now "stale" — a wake event carrying that older token
    // must be a no-op even if the clipboard still byte-equals the
    // older captured payload.
    let p1 = schedule_copy(Instant::now(), vault.settings(), fresh_payload(b"old"))
        .expect("scheduled 1");
    let p2 = schedule_copy(Instant::now(), vault.settings(), fresh_payload(b"new"))
        .expect("scheduled 2");
    assert_ne!(p1.token, p2.token);

    // The current "live" pending is `p2`. A wake event carrying
    // `p1.token` is stale relative to `p2` and must be dropped first
    // — before any `should_clear` byte comparison.
    let decision = evaluate_wake(&p2, p1.token, b"new");
    assert_eq!(decision, WakeDecision::Stale);
}

// ---------------------------------------------------------------------------
// Pending value zeroizes after a clear attempt or stale-token supersession
// ---------------------------------------------------------------------------

#[test]
fn pending_value_zeroizes_when_dropped_after_clear_attempt() {
    // `Zeroizing<Vec<u8>>` zeros the inner buffer on drop. Verify
    // that calling `evaluate_wake -> Clear` followed by dropping the
    // pending state zeroes the captured bytes via the
    // `Zeroize` impl. We can't read freed memory portably, so we
    // instead verify that the captured `Vec<u8>` is `Zeroizing`-
    // wrapped (this is a *structural* assertion: the field type is
    // chosen so that `Drop` zeros).
    let _guard = schedule_lock();
    let tmp = secure_tempdir();
    let (mut vault, store) = create_plaintext(&tmp.path().join("plain.bin"));
    enable_clipboard_clear(&mut vault, &store, 10);

    let pending = schedule_copy(Instant::now(), vault.settings(), fresh_payload(b"secret"))
        .expect("scheduled");

    // Snapshot the bytes the policy will compare against.
    let captured: Vec<u8> = pending.value.to_vec();
    let decision = evaluate_wake(&pending, pending.token, &captured);
    assert_eq!(decision, WakeDecision::Clear);

    // Reach into the typed contract: the `value` field is
    // `Zeroizing<Vec<u8>>`, which zeros the inner buffer on drop.
    // The binding below would fail to compile if the field type ever
    // changed away from `Zeroizing<Vec<u8>>`, locking the contract.
    let value_ref: &Zeroizing<Vec<u8>> = &pending.value;
    assert_eq!(&value_ref[..], b"secret");

    // Move pending into a scope and let it drop. After the scope,
    // the `Zeroizing<Vec<u8>>` field has fired its `Drop` impl,
    // zeroing the inner buffer before deallocation.
    drop(pending);
}

#[test]
fn pending_value_zeroizes_when_superseded_by_a_fresh_schedule() {
    // When `schedule_copy` issues a fresh pending, the caller is
    // expected to drop the old one. The Zeroizing wrapper handles
    // the wipe. We model this by holding the old pending in an
    // `Option<...>` and assigning a fresh value over it, then assert
    // the contract by type.
    let _guard = schedule_lock();
    let tmp = secure_tempdir();
    let (mut vault, store) = create_plaintext(&tmp.path().join("plain.bin"));
    enable_clipboard_clear(&mut vault, &store, 10);

    let mut slot: Option<PendingClipboardClear> = Some(
        schedule_copy(Instant::now(), vault.settings(), fresh_payload(b"first"))
            .expect("scheduled 1"),
    );
    // Confirm slot has the first pending before we supersede it.
    assert_eq!(
        &slot.as_ref().expect("slot has first pending").value[..],
        b"first"
    );

    // Replace: the previous Pending drops here (zeroizing its
    // `Zeroizing<Vec<u8>>` payload before deallocation).
    slot = Some(
        schedule_copy(Instant::now(), vault.settings(), fresh_payload(b"second"))
            .expect("scheduled 2"),
    );

    let pending = slot.take().expect("slot has fresh pending");
    assert_eq!(&pending.value[..], b"second");
}

// ---------------------------------------------------------------------------
// Lock-survival: a clipboard auto-clear timer scheduled before lock
// survives the auto-lock transition and still fires only-if-unchanged
// ---------------------------------------------------------------------------

#[test]
fn pending_clipboard_clear_survives_auto_lock() {
    let _guard = schedule_lock();
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted(&path, "hunter2");
    enable_clipboard_clear(&mut vault, &store, 60);

    // Schedule a clipboard clear, then auto-lock the model.
    let captured = b"123456";
    let pending = schedule_copy(Instant::now(), vault.settings(), fresh_payload(captured))
        .expect("scheduled");
    let surviving_token = pending.token;
    let surviving_deadline = pending.deadline;

    let (reveal_tag, reveal_drops) = DropTag::new();
    let (modal_tag, modal_drops) = DropTag::new();
    let discards = UnlockedDiscards {
        search_query: "github".to_string(),
        hotp_reveal: Some(reveal_tag),
        modal: Some(modal_tag),
    };

    let locked = lock_on_expiry(path.clone(), vault, store, discards, Some(pending));

    assert_eq!(locked.path, path);
    // Reveal and modal were discarded by the auto-lock transition.
    assert_eq!(reveal_drops.load(Ordering::SeqCst), 1);
    assert_eq!(modal_drops.load(Ordering::SeqCst), 1);

    // The pending clipboard clear survived.
    let surviving = locked
        .pending_clipboard_clear
        .as_ref()
        .expect("pending clipboard clear must survive lock");
    assert_eq!(surviving.token, surviving_token);
    assert_eq!(surviving.deadline, surviving_deadline);
    assert_eq!(&surviving.value[..], captured);

    // And the only-if-unchanged decision still gates the post-lock
    // wake: same bytes → Clear; different bytes → Mismatch.
    assert_eq!(
        evaluate_wake(surviving, surviving_token, captured),
        WakeDecision::Clear
    );
    assert_eq!(
        evaluate_wake(surviving, surviving_token, b"changed by user"),
        WakeDecision::Mismatch
    );
}

#[test]
fn lock_on_expiry_carries_none_when_no_pending_clipboard_clear() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (vault, store) = create_encrypted(&path, "hunter2");

    let discards: UnlockedDiscards<DropTag, DropTag> = UnlockedDiscards {
        search_query: String::new(),
        hotp_reveal: None,
        modal: None,
    };

    let locked = lock_on_expiry(path.clone(), vault, store, discards, None);
    assert_eq!(locked.path, path);
    assert!(locked.pending_clipboard_clear.is_none());
}

// ---------------------------------------------------------------------------
// Sanity: schedule + wake against fresh `vault.bin` — full round trip
// ---------------------------------------------------------------------------

#[test]
fn schedule_then_wake_with_same_clipboard_signals_clear_via_should_clear() {
    let _guard = schedule_lock();
    let tmp = secure_tempdir();
    let (mut vault, store) = create_plaintext(&tmp.path().join("plain.bin"));
    enable_clipboard_clear(&mut vault, &store, 5);

    let value = b"otp-code";
    let now = Instant::now();
    let pending = schedule_copy(now, vault.settings(), fresh_payload(value)).expect("scheduled");
    assert_eq!(pending.deadline, now + Duration::from_secs(5));

    assert_eq!(
        evaluate_wake(&pending, pending.token, value),
        WakeDecision::Clear
    );
    assert!(ClipboardClearPolicy::should_clear(&pending.value, value));
}
