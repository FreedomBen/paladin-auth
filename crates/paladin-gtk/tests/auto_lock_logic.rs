// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic auto-lock tests for `paladin-gtk`.
//!
//! Tracks the §"Tests > Pure-logic unit tests > `tests/auto_lock_logic.rs`"
//! checklist in `IMPLEMENTATION_PLAN_04_GTK.md`:
//!
//! * Idle-event source feeds
//!   `paladin_core::policy::auto_lock::IdlePolicy::should_arm` /
//!   `next_deadline` / `is_expired` outcomes correctly for both
//!   encrypted and plaintext vaults (plaintext returns `None` from
//!   core, not via a GUI shortcut).
//! * Re-arm decision after a successful `PassphraseDialog` transition
//!   re-asks `IdlePolicy::should_arm` against the new
//!   `Vault::is_encrypted()` value.
//! * On expiry, the model drops `Vault`, switches to `Locked`, and
//!   discards open HOTP reveal windows, the search query, and any open
//!   dialog.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use secrecy::SecretString;
use tempfile::TempDir;

use paladin_core::policy::auto_lock::IdlePolicy;
use paladin_core::{
    Argon2Params, EncryptionOptions, Store, Vault, VaultInit, VaultLock, VaultSettings,
};

use paladin_gtk::auto_lock::{
    idle_event_deadline, idle_should_arm, is_expired, lock_on_expiry, UnlockedDiscards,
};

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

// ---------------------------------------------------------------------------
// idle_event_deadline / idle_should_arm — route through IdlePolicy
// ---------------------------------------------------------------------------

#[test]
fn idle_event_deadline_armed_for_encrypted_with_auto_lock_enabled() {
    let tmp = secure_tempdir();
    let (mut vault, store) = create_encrypted(&tmp.path().join("vault.bin"), "hunter2");
    vault.set_auto_lock_enabled(true);
    vault.set_auto_lock_timeout_secs(45).unwrap();
    vault.save(&store).unwrap();

    let now = Instant::now();
    let got = idle_event_deadline(now, &vault);

    let expected = IdlePolicy::next_deadline(now, true, vault.settings());
    assert_eq!(got, Some(now + Duration::from_secs(45)));
    assert_eq!(got, expected, "must match IdlePolicy::next_deadline");
}

#[test]
fn idle_event_deadline_uses_default_timeout_300_when_unchanged() {
    let tmp = secure_tempdir();
    let (mut vault, store) = create_encrypted(&tmp.path().join("vault.bin"), "hunter2");
    vault.set_auto_lock_enabled(true);
    vault.save(&store).unwrap();
    assert_eq!(vault.settings().auto_lock_timeout_secs(), 300);

    let now = Instant::now();
    assert_eq!(
        idle_event_deadline(now, &vault),
        Some(now + Duration::from_secs(300))
    );
}

#[test]
fn idle_event_deadline_none_for_encrypted_when_auto_lock_disabled() {
    let tmp = secure_tempdir();
    let (vault, _store) = create_encrypted(&tmp.path().join("vault.bin"), "hunter2");
    assert!(!vault.settings().auto_lock_enabled(), "default is false");

    assert_eq!(idle_event_deadline(Instant::now(), &vault), None);
}

#[test]
fn idle_event_deadline_none_for_plaintext_even_when_auto_lock_enabled() {
    // Plaintext-no-op rule must come from core (IdlePolicy::should_arm),
    // not from a GUI-side shortcut.
    let tmp = secure_tempdir();
    let (mut vault, store) = create_plaintext(&tmp.path().join("plain.bin"));
    vault.set_auto_lock_enabled(true);
    vault.set_auto_lock_timeout_secs(60).unwrap();
    vault.save(&store).unwrap();
    assert!(vault.settings().auto_lock_enabled());

    assert_eq!(idle_event_deadline(Instant::now(), &vault), None);
}

#[test]
fn idle_should_arm_matches_policy_for_encrypted() {
    let tmp = secure_tempdir();
    let (mut vault, store) = create_encrypted(&tmp.path().join("vault.bin"), "hunter2");
    assert!(
        !idle_should_arm(&vault),
        "default auto_lock_enabled is false"
    );

    vault.set_auto_lock_enabled(true);
    vault.save(&store).unwrap();
    assert!(idle_should_arm(&vault));
    assert_eq!(
        idle_should_arm(&vault),
        IdlePolicy::should_arm(true, vault.settings())
    );
}

#[test]
fn idle_should_arm_false_for_plaintext_regardless_of_setting() {
    let tmp = secure_tempdir();
    let (mut vault, store) = create_plaintext(&tmp.path().join("plain.bin"));
    assert!(!idle_should_arm(&vault));

    vault.set_auto_lock_enabled(true);
    vault.save(&store).unwrap();
    assert!(!idle_should_arm(&vault));
    assert_eq!(
        idle_should_arm(&vault),
        IdlePolicy::should_arm(false, vault.settings())
    );
}

// ---------------------------------------------------------------------------
// is_expired — strict monotonic comparison via IdlePolicy
// ---------------------------------------------------------------------------

#[test]
fn is_expired_matches_idle_policy_semantics() {
    let now = Instant::now();
    let deadline = now + Duration::from_secs(10);

    assert!(!is_expired(deadline, now));
    assert!(!is_expired(deadline, now + Duration::from_secs(9)));
    // Equal counts as expired (DESIGN: a tick that lands on the
    // deadline fires the lock).
    assert!(is_expired(deadline, deadline));
    assert!(is_expired(deadline, now + Duration::from_secs(11)));
    assert_eq!(
        is_expired(deadline, deadline + Duration::from_millis(1)),
        IdlePolicy::is_expired(deadline, deadline + Duration::from_millis(1)),
    );
}

// ---------------------------------------------------------------------------
// Re-arm decision after a passphrase transition tracks the new vault mode
// ---------------------------------------------------------------------------

#[test]
fn re_arm_after_passphrase_transition_uses_new_is_encrypted() {
    // Simulate a `PassphraseDialog` transition by reopening the vault
    // file in a new mode and re-asking `idle_should_arm` /
    // `idle_event_deadline`. The decision must follow the new
    // `is_encrypted()` value without re-inspecting the file ourselves.
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");

    // Start encrypted with auto-lock enabled and a custom timeout.
    let (mut enc_vault, enc_store) = create_encrypted(&path, "hunter2");
    enc_vault.set_auto_lock_enabled(true);
    enc_vault.set_auto_lock_timeout_secs(120).unwrap();
    enc_vault.save(&enc_store).unwrap();

    assert!(idle_should_arm(&enc_vault));
    let now = Instant::now();
    assert_eq!(
        idle_event_deadline(now, &enc_vault),
        Some(now + Duration::from_secs(120))
    );

    // Hand-roll a "remove passphrase" transition: reopen via a new
    // plaintext-mode vault sharing the same settings.
    let tmp2 = secure_tempdir();
    let plain_path = tmp2.path().join("vault.bin");
    let (mut plain_vault, plain_store) = create_plaintext(&plain_path);
    plain_vault.set_auto_lock_enabled(true);
    plain_vault.set_auto_lock_timeout_secs(120).unwrap();
    plain_vault.save(&plain_store).unwrap();

    // After the transition to plaintext, re-arming must report `false`
    // and the deadline must be `None` — even though the setting still
    // persists for the encrypted-later case.
    assert!(!idle_should_arm(&plain_vault));
    assert_eq!(idle_event_deadline(Instant::now(), &plain_vault), None);
}

#[test]
fn re_arm_after_setting_passphrase_on_plaintext_arms_the_timer() {
    // The inverse: a plaintext vault with auto-lock enabled stays
    // unarmed; after the user sets a passphrase (transition to
    // encrypted), the re-arm decision returns `true` against the new
    // `is_encrypted()` value.
    let tmp = secure_tempdir();
    let plain_path = tmp.path().join("vault.bin");
    let (mut plain_vault, plain_store) = create_plaintext(&plain_path);
    plain_vault.set_auto_lock_enabled(true);
    plain_vault.set_auto_lock_timeout_secs(60).unwrap();
    plain_vault.save(&plain_store).unwrap();
    assert!(!idle_should_arm(&plain_vault));

    // Stand-in for `PassphraseDialog::set_passphrase` — open a new
    // encrypted vault that carries the same settings forward.
    let tmp2 = secure_tempdir();
    let enc_path = tmp2.path().join("vault.bin");
    let (mut enc_vault, enc_store) = create_encrypted(&enc_path, "hunter2");
    enc_vault.set_auto_lock_enabled(true);
    enc_vault.set_auto_lock_timeout_secs(60).unwrap();
    enc_vault.save(&enc_store).unwrap();

    assert!(idle_should_arm(&enc_vault));
    let now = Instant::now();
    assert_eq!(
        idle_event_deadline(now, &enc_vault),
        Some(now + Duration::from_secs(60))
    );
}

// ---------------------------------------------------------------------------
// `lock_on_expiry` discards Vault, search query, HOTP reveal, and any modal
// ---------------------------------------------------------------------------

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

#[test]
fn lock_on_expiry_carries_only_the_path_forward() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (vault, store) = create_encrypted(&path, "hunter2");

    let (reveal_tag, reveal_drops) = DropTag::new();
    let (modal_tag, modal_drops) = DropTag::new();

    let discards = UnlockedDiscards {
        search_query: "github".to_string(),
        hotp_reveal: Some(reveal_tag),
        modal: Some(modal_tag),
    };

    let locked = lock_on_expiry(path.clone(), vault, store, discards);

    assert_eq!(locked.path, path);
    // The transition takes the values by move and drops them; nothing
    // else survives. The only carried-forward state is the path.
    assert_eq!(
        reveal_drops.load(Ordering::SeqCst),
        1,
        "HOTP reveal window must be discarded on auto-lock"
    );
    assert_eq!(
        modal_drops.load(Ordering::SeqCst),
        1,
        "open dialog (modal) must be discarded on auto-lock"
    );
}

#[test]
fn lock_on_expiry_discards_open_reveal_and_modal_when_none() {
    // When the unlocked state had no reveal / modal active, the
    // transition still produces a `Locked` snapshot with only the path.
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (vault, store) = create_encrypted(&path, "hunter2");

    let discards: UnlockedDiscards<DropTag, DropTag> = UnlockedDiscards {
        search_query: String::new(),
        hotp_reveal: None,
        modal: None,
    };

    let locked = lock_on_expiry(path.clone(), vault, store, discards);
    assert_eq!(locked.path, path);
}

#[test]
fn lock_on_expiry_drops_vault_so_secrets_do_not_outlive_lock() {
    // The transition consumes `vault` and `store` by value so callers
    // cannot smuggle a `Vault` past the lock. Verify by re-opening the
    // file after the transition — the on-disk vault is still readable
    // (plaintext path here for simplicity), but the in-memory `Vault`
    // we passed in has been dropped (not stashed inside
    // `LockedTransition`).
    let tmp = secure_tempdir();
    let path = tmp.path().join("plain.bin");
    let (vault, store) = create_plaintext(&path);

    let discards: UnlockedDiscards<DropTag, DropTag> = UnlockedDiscards {
        search_query: "q".to_string(),
        hotp_reveal: None,
        modal: None,
    };

    let locked = lock_on_expiry(path.clone(), vault, store, discards);
    assert_eq!(locked.path, path);

    // Re-opening the on-disk vault still works (the in-memory copy is
    // gone, but the file is unchanged).
    let (_reopened, _store) =
        Store::open(&locked.path, VaultLock::Plaintext).expect("reopen plaintext after lock");
}

// ---------------------------------------------------------------------------
// `VaultSettings::default()` is unarmed even with `next_deadline` from `now`
// ---------------------------------------------------------------------------

#[test]
fn default_settings_never_arms_via_idle_policy_route() {
    // Sanity check: the default `VaultSettings` (auto-lock disabled)
    // routes through `idle_should_arm` / `idle_event_deadline` as
    // `false` / `None`, regardless of encryption mode.
    let settings = VaultSettings::default();
    assert!(!settings.auto_lock_enabled());

    assert!(!IdlePolicy::should_arm(true, &settings));
    assert!(!IdlePolicy::should_arm(false, &settings));

    let now = Instant::now();
    assert_eq!(IdlePolicy::next_deadline(now, true, &settings), None);
    assert_eq!(IdlePolicy::next_deadline(now, false, &settings), None);
}
