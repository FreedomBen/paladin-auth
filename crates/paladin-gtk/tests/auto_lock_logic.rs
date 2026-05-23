// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic auto-lock tests for `paladin-gtk`.
//!
//! Tracks the §"Tests > Pure-logic unit tests > `tests/auto_lock_logic.rs`"
//! checklist in `docs/IMPLEMENTATION_PLAN_04_GTK.md`:
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
    auto_lock_timer_transition, evaluate_timer_fire, idle_event_deadline, idle_should_arm,
    is_expired, lock_on_expiry, refresh_idle_source_after_passphrase, AutoLockFireDecision,
    AutoLockTimerTransition, IdleSource, UnlockedDiscards,
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
// refresh_idle_source_after_passphrase — wire-up helper for the
// `PassphraseWorkerCompleted` handler in `app::model`.
//
// Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Clipboard + auto-lock parity
// with TUI" — "Re-ask `IdlePolicy::should_arm` after every successful
// `PassphraseDialog` transition so arm/disarm tracks the on-disk vault
// mode without re-inspecting the file." The gating `Option<bool>`
// carries the typed `PassphraseDispatch::new_is_encrypted` projection:
// `Some(_)` on success (any of `set` / `change` / `remove`) refreshes
// the source against the reinstalled vault; `None` on every failure
// branch leaves the source untouched because DESIGN §4.5 owns the
// in-memory rollback / replacement.
// ---------------------------------------------------------------------------

#[test]
fn refresh_idle_source_after_passphrase_remove_disarms_armed_source() {
    // `PassphraseDialog::remove` flips the vault to plaintext. The
    // helper must refresh the source against the new vault so the
    // armed deadline clears via `IdlePolicy::next_deadline`'s
    // plaintext-no-op rule.
    let tmp = secure_tempdir();
    let (mut enc_vault, enc_store) = create_encrypted(&tmp.path().join("vault.bin"), "hunter2");
    enc_vault.set_auto_lock_enabled(true);
    enc_vault.set_auto_lock_timeout_secs(60).unwrap();
    enc_vault.save(&enc_store).unwrap();

    let mut src = IdleSource::new();
    src.refresh(Instant::now(), &enc_vault)
        .expect("armed before transition");
    assert!(src.is_armed());

    // Stand-in for the post-`remove` reinstalled vault.
    let tmp2 = secure_tempdir();
    let (mut plain_vault, plain_store) = create_plaintext(&tmp2.path().join("plain.bin"));
    plain_vault.set_auto_lock_enabled(true);
    plain_vault.set_auto_lock_timeout_secs(60).unwrap();
    plain_vault.save(&plain_store).unwrap();

    let refreshed =
        refresh_idle_source_after_passphrase(&mut src, Some(false), &plain_vault, Instant::now());

    assert!(refreshed, "success branch must refresh the source");
    assert!(!src.is_armed(), "plaintext mode disarms via the policy");
    assert_eq!(src.deadline(), None);
}

#[test]
fn refresh_idle_source_after_passphrase_set_arms_disarmed_source() {
    // `PassphraseDialog::set` flips a plaintext vault to encrypted.
    // A previously disarmed source must arm against the new vault.
    let tmp = secure_tempdir();
    let (mut enc_vault, enc_store) = create_encrypted(&tmp.path().join("vault.bin"), "hunter2");
    enc_vault.set_auto_lock_enabled(true);
    enc_vault.set_auto_lock_timeout_secs(90).unwrap();
    enc_vault.save(&enc_store).unwrap();

    let mut src = IdleSource::new();
    assert!(!src.is_armed(), "disarmed before transition");

    let now = Instant::now();
    let refreshed = refresh_idle_source_after_passphrase(&mut src, Some(true), &enc_vault, now);

    assert!(refreshed);
    assert!(src.is_armed());
    assert_eq!(src.deadline(), Some(now + Duration::from_secs(90)));
}

#[test]
fn refresh_idle_source_after_passphrase_change_rolls_deadline_forward() {
    // `PassphraseDialog::change` keeps the vault encrypted. A prior
    // armed deadline must be replaced by a fresh one computed against
    // the new `now`, matching the `IdleEvent` refresh contract.
    let tmp = secure_tempdir();
    let (mut vault, store) = create_encrypted(&tmp.path().join("vault.bin"), "hunter2");
    vault.set_auto_lock_enabled(true);
    vault.set_auto_lock_timeout_secs(120).unwrap();
    vault.save(&store).unwrap();

    let armed_at = Instant::now();
    let mut src = IdleSource::new();
    let initial = src.refresh(armed_at, &vault).expect("armed initially");

    let later = armed_at + Duration::from_secs(45);
    let refreshed = refresh_idle_source_after_passphrase(&mut src, Some(true), &vault, later);

    assert!(refreshed);
    assert!(src.is_armed());
    let new_deadline = src.deadline().expect("still armed after change");
    assert_eq!(new_deadline, later + Duration::from_secs(120));
    assert!(
        new_deadline > initial,
        "passphrase change rolls the deadline forward against the new now"
    );
}

#[test]
fn refresh_idle_source_after_passphrase_failure_leaves_armed_source_untouched() {
    // `None` is the failure branch (any of `save_not_committed` /
    // `save_durability_unconfirmed` / typed defensive error). The
    // helper must not poke the source — DESIGN §4.5 owns the
    // in-memory rollback / replacement.
    let tmp = secure_tempdir();
    let (mut vault, store) = create_encrypted(&tmp.path().join("vault.bin"), "hunter2");
    vault.set_auto_lock_enabled(true);
    vault.set_auto_lock_timeout_secs(60).unwrap();
    vault.save(&store).unwrap();

    let armed_at = Instant::now();
    let mut src = IdleSource::new();
    let before = src.refresh(armed_at, &vault).expect("armed");
    let before_state = src;

    let later = armed_at + Duration::from_secs(7);
    let refreshed = refresh_idle_source_after_passphrase(&mut src, None, &vault, later);

    assert!(!refreshed, "failure branch must report no refresh");
    assert_eq!(
        src, before_state,
        "failure branch must leave the source bit-identical"
    );
    assert_eq!(src.deadline(), Some(before));
}

#[test]
fn refresh_idle_source_after_passphrase_failure_leaves_disarmed_source_untouched() {
    // The defensive pair of the prior test: a disarmed source stays
    // disarmed across a failure outcome.
    let tmp = secure_tempdir();
    let (vault, _store) = create_plaintext(&tmp.path().join("plain.bin"));

    let mut src = IdleSource::new();
    assert!(!src.is_armed());

    let refreshed = refresh_idle_source_after_passphrase(&mut src, None, &vault, Instant::now());

    assert!(!refreshed);
    assert!(!src.is_armed());
    assert_eq!(src.deadline(), None);
}

#[test]
fn refresh_idle_source_after_passphrase_with_disabled_setting_disarms() {
    // Even when the post-transition vault is encrypted, the
    // `auto_lock_enabled` setting still gates arming through the
    // policy. The helper must route through `IdleSource::refresh`,
    // not bypass it — so an encrypted vault with the toggle off
    // disarms the source.
    let tmp = secure_tempdir();
    let (vault, _store) = create_encrypted(&tmp.path().join("vault.bin"), "hunter2");
    assert!(
        !vault.settings().auto_lock_enabled(),
        "default is false (opt-in)"
    );

    let mut src = IdleSource::new();
    let refreshed =
        refresh_idle_source_after_passphrase(&mut src, Some(true), &vault, Instant::now());

    assert!(refreshed, "success branch always reports a refresh");
    assert!(
        !src.is_armed(),
        "opt-out gate lives in the policy, not in the helper"
    );
    assert_eq!(src.deadline(), None);
}

#[test]
fn refresh_idle_source_after_passphrase_matches_idle_source_refresh_on_success() {
    // Sanity: on the success branch, the helper produces the same
    // deadline as calling `IdleSource::refresh` directly, so the GUI
    // cannot drift between the dispatch-gated and bare routes.
    let tmp = secure_tempdir();
    let (mut vault, store) = create_encrypted(&tmp.path().join("vault.bin"), "hunter2");
    vault.set_auto_lock_enabled(true);
    vault.set_auto_lock_timeout_secs(150).unwrap();
    vault.save(&store).unwrap();

    let now = Instant::now();
    let mut helper_src = IdleSource::new();
    let mut bare_src = IdleSource::new();

    let _ = refresh_idle_source_after_passphrase(&mut helper_src, Some(true), &vault, now);
    bare_src.refresh(now, &vault);

    assert_eq!(helper_src, bare_src);
    assert_eq!(helper_src.deadline(), Some(now + Duration::from_secs(150)));
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

    let locked = lock_on_expiry(path.clone(), vault, store, discards, None);

    assert_eq!(locked.path, path);
    // The transition takes the values by move and drops them; the
    // only carried-forward fields are the path and any pending
    // clipboard auto-clear (None here — covered in clipboard_clear_logic).
    assert!(locked.pending_clipboard_clear.is_none());
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

    let locked = lock_on_expiry(path.clone(), vault, store, discards, None);
    assert_eq!(locked.path, path);
    assert!(locked.pending_clipboard_clear.is_none());
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

    let locked = lock_on_expiry(path.clone(), vault, store, discards, None);
    assert_eq!(locked.path, path);
    assert!(locked.pending_clipboard_clear.is_none());

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

// ---------------------------------------------------------------------------
// `IdleSource` — the GTK side's record of the current armed deadline.
//
// The GUI wires `gtk::EventControllerKey` / `gtk::EventControllerMotion`
// at the `AppModel` root; each event refreshes the deadline through
// `IdleSource::refresh`, which routes through `IdlePolicy::next_deadline`
// so the plaintext-no-op and arm rules live in core, not in the wiring.
// ---------------------------------------------------------------------------

#[test]
fn idle_source_new_is_disarmed() {
    let src = IdleSource::new();
    assert_eq!(src.deadline(), None);
    assert!(!src.is_armed());
    assert!(!src.is_expired(Instant::now()));
}

#[test]
fn idle_source_default_matches_new() {
    let default_src = IdleSource::default();
    let new_src = IdleSource::new();
    assert_eq!(default_src.deadline(), new_src.deadline());
    assert_eq!(default_src.is_armed(), new_src.is_armed());
}

#[test]
fn idle_source_refresh_arms_for_encrypted_with_enabled_setting() {
    let tmp = secure_tempdir();
    let (mut vault, store) = create_encrypted(&tmp.path().join("vault.bin"), "hunter2");
    vault.set_auto_lock_enabled(true);
    vault.set_auto_lock_timeout_secs(45).unwrap();
    vault.save(&store).unwrap();

    let mut src = IdleSource::new();
    let now = Instant::now();
    let armed = src.refresh(now, &vault);

    assert_eq!(armed, Some(now + Duration::from_secs(45)));
    assert_eq!(src.deadline(), armed);
    assert!(src.is_armed());

    // Pinned to the policy, not a GUI shortcut.
    assert_eq!(
        armed,
        IdlePolicy::next_deadline(now, true, vault.settings())
    );
}

#[test]
fn idle_source_refresh_disarms_plaintext_regardless_of_setting() {
    // Plaintext vaults always disarm — the rule lives in
    // `IdlePolicy::should_arm`, not in `IdleSource`.
    let tmp = secure_tempdir();
    let (mut vault, store) = create_plaintext(&tmp.path().join("plain.bin"));
    vault.set_auto_lock_enabled(true);
    vault.set_auto_lock_timeout_secs(60).unwrap();
    vault.save(&store).unwrap();

    let mut src = IdleSource::new();
    assert_eq!(src.refresh(Instant::now(), &vault), None);
    assert!(!src.is_armed());
    assert_eq!(src.deadline(), None);
}

#[test]
fn idle_source_refresh_disarms_when_setting_is_off() {
    let tmp = secure_tempdir();
    let (vault, _store) = create_encrypted(&tmp.path().join("vault.bin"), "hunter2");
    assert!(
        !vault.settings().auto_lock_enabled(),
        "default is false (opt-in)"
    );

    let mut src = IdleSource::new();
    assert_eq!(src.refresh(Instant::now(), &vault), None);
    assert!(!src.is_armed());
}

#[test]
fn idle_source_refresh_after_prior_arm_resets_against_new_now() {
    // Every idle event (key press / pointer motion) pushes the
    // deadline forward by exactly `auto_lock_timeout_secs` — the
    // policy returns `now + timeout`, so a later refresh sees a
    // later deadline.
    let tmp = secure_tempdir();
    let (mut vault, store) = create_encrypted(&tmp.path().join("vault.bin"), "hunter2");
    vault.set_auto_lock_enabled(true);
    vault.set_auto_lock_timeout_secs(60).unwrap();
    vault.save(&store).unwrap();

    let mut src = IdleSource::new();
    let t1 = Instant::now();
    let d1 = src.refresh(t1, &vault).expect("armed at t1");

    let t2 = t1 + Duration::from_secs(7);
    let d2 = src.refresh(t2, &vault).expect("armed at t2");

    assert_eq!(d1, t1 + Duration::from_secs(60));
    assert_eq!(d2, t2 + Duration::from_secs(60));
    assert!(d2 > d1, "later idle event must produce a later deadline");
    assert_eq!(src.deadline(), Some(d2));
}

#[test]
fn idle_source_refresh_can_disarm_a_previously_armed_source() {
    // A passphrase-remove transition flips the vault to plaintext;
    // re-asking `refresh` with the new vault must clear the prior
    // armed deadline so the timer code never sees a stale value.
    let tmp = secure_tempdir();
    let (mut enc_vault, enc_store) = create_encrypted(&tmp.path().join("vault.bin"), "hunter2");
    enc_vault.set_auto_lock_enabled(true);
    enc_vault.set_auto_lock_timeout_secs(60).unwrap();
    enc_vault.save(&enc_store).unwrap();

    let mut src = IdleSource::new();
    assert!(src.refresh(Instant::now(), &enc_vault).is_some());
    assert!(src.is_armed());

    let tmp2 = secure_tempdir();
    let (mut plain_vault, plain_store) = create_plaintext(&tmp2.path().join("plain.bin"));
    plain_vault.set_auto_lock_enabled(true);
    plain_vault.set_auto_lock_timeout_secs(60).unwrap();
    plain_vault.save(&plain_store).unwrap();

    assert_eq!(src.refresh(Instant::now(), &plain_vault), None);
    assert!(!src.is_armed());
    assert_eq!(src.deadline(), None);
}

#[test]
fn idle_source_is_expired_matches_policy_when_armed() {
    let tmp = secure_tempdir();
    let (mut vault, store) = create_encrypted(&tmp.path().join("vault.bin"), "hunter2");
    vault.set_auto_lock_enabled(true);
    // 30 s is `AUTO_LOCK_SECS_MIN` — the smallest accepted setting.
    vault.set_auto_lock_timeout_secs(30).unwrap();
    vault.save(&store).unwrap();

    let mut src = IdleSource::new();
    let now = Instant::now();
    let deadline = src.refresh(now, &vault).expect("armed");

    assert!(!src.is_expired(now));
    assert!(!src.is_expired(now + Duration::from_secs(29)));
    assert!(
        src.is_expired(deadline),
        "tick that lands on the deadline fires the lock"
    );
    assert!(src.is_expired(now + Duration::from_secs(31)));
    assert_eq!(
        src.is_expired(now + Duration::from_secs(31)),
        is_expired(deadline, now + Duration::from_secs(31)),
    );
}

#[test]
fn idle_source_is_expired_returns_false_when_disarmed() {
    // A disarmed source never reports expiry, even far in the
    // future — the timer must not fire while plaintext / opted-out.
    let src = IdleSource::new();
    assert!(!src.is_expired(Instant::now() + Duration::from_secs(86_400)));
    assert!(!src.is_expired(Instant::now()));
}

#[test]
fn idle_source_disarm_clears_deadline() {
    let tmp = secure_tempdir();
    let (mut vault, store) = create_encrypted(&tmp.path().join("vault.bin"), "hunter2");
    vault.set_auto_lock_enabled(true);
    vault.save(&store).unwrap();

    let mut src = IdleSource::new();
    src.refresh(Instant::now(), &vault).expect("armed");
    assert!(src.is_armed());

    src.disarm();
    assert!(!src.is_armed());
    assert_eq!(src.deadline(), None);
    assert!(!src.is_expired(Instant::now() + Duration::from_secs(3_600)));
}

#[test]
fn idle_source_refresh_consistent_with_idle_event_deadline_helper() {
    // Sanity: `IdleSource::refresh` and the bare
    // `idle_event_deadline` helper produce the same value, so the
    // GUI cannot drift between the stateful and pure-function
    // routes.
    let tmp = secure_tempdir();
    let (mut vault, store) = create_encrypted(&tmp.path().join("vault.bin"), "hunter2");
    vault.set_auto_lock_enabled(true);
    vault.set_auto_lock_timeout_secs(180).unwrap();
    vault.save(&store).unwrap();

    let now = Instant::now();
    let mut src = IdleSource::new();
    let armed = src.refresh(now, &vault);

    assert_eq!(armed, idle_event_deadline(now, &vault));
    assert!(idle_should_arm(&vault));
}

// ---------------------------------------------------------------------------
// `auto_lock_timer_transition` — pure-logic driver for the
// `glib::timeout_add_local` source that backs the auto-lock countdown.
//
// Mirrors `ticker_transition`'s four-cell truth table so the widget
// layer's install / teardown call sites stay exhaustive and the
// `IdlePolicy` arm/disarm decision lives in core.
// ---------------------------------------------------------------------------

#[test]
fn auto_lock_timer_transition_install_when_armed_and_not_installed() {
    // Fresh unlock: IdleSource just armed for an encrypted opted-in
    // vault, no timer running yet → install a fresh source.
    let tmp = secure_tempdir();
    let (mut vault, store) = create_encrypted(&tmp.path().join("vault.bin"), "hunter2");
    vault.set_auto_lock_enabled(true);
    vault.set_auto_lock_timeout_secs(60).unwrap();
    vault.save(&store).unwrap();

    let now = Instant::now();
    let mut src = IdleSource::new();
    src.refresh(now, &vault).expect("armed");

    let transition = auto_lock_timer_transition(false, &src, now);
    assert_eq!(
        transition,
        AutoLockTimerTransition::Install(Duration::from_secs(60))
    );
}

#[test]
fn auto_lock_timer_transition_teardown_when_disarmed_and_installed() {
    // The vault transitioned to plaintext (or the user disabled
    // auto-lock) while a timer was running → tear down.
    let src = IdleSource::new();
    let now = Instant::now();
    assert!(!src.is_armed());

    let transition = auto_lock_timer_transition(true, &src, now);
    assert_eq!(transition, AutoLockTimerTransition::Teardown);
}

#[test]
fn auto_lock_timer_transition_nochange_when_armed_and_installed() {
    // Steady state during an unlocked encrypted session: the timer
    // is running, the source still has an armed deadline. The
    // existing one-shot source will fire and `evaluate_timer_fire`
    // re-arms if needed — no churn on every idle event.
    let tmp = secure_tempdir();
    let (mut vault, store) = create_encrypted(&tmp.path().join("vault.bin"), "hunter2");
    vault.set_auto_lock_enabled(true);
    vault.save(&store).unwrap();

    let now = Instant::now();
    let mut src = IdleSource::new();
    src.refresh(now, &vault).expect("armed");

    let transition = auto_lock_timer_transition(true, &src, now);
    assert_eq!(transition, AutoLockTimerTransition::NoChange);
}

#[test]
fn auto_lock_timer_transition_nochange_when_disarmed_and_not_installed() {
    // Steady state in `Missing` / `Locked` / `StartupError` or for a
    // plaintext / opted-out unlocked vault: nothing armed, nothing
    // installed — no `glib::source_remove` calls and no install.
    let src = IdleSource::new();
    let now = Instant::now();

    let transition = auto_lock_timer_transition(false, &src, now);
    assert_eq!(transition, AutoLockTimerTransition::NoChange);
}

#[test]
fn auto_lock_timer_transition_install_uses_deadline_minus_now() {
    // The install variant carries the exact `Duration` to pass to
    // `glib::timeout_add_local` — derived from `deadline - now`, not
    // a fresh `auto_lock_timeout_secs` fetch — so a stale deadline
    // (refresh skipped between probe and install) still produces a
    // tight wake.
    let tmp = secure_tempdir();
    let (mut vault, store) = create_encrypted(&tmp.path().join("vault.bin"), "hunter2");
    vault.set_auto_lock_enabled(true);
    vault.set_auto_lock_timeout_secs(120).unwrap();
    vault.save(&store).unwrap();

    let armed_at = Instant::now();
    let mut src = IdleSource::new();
    src.refresh(armed_at, &vault).expect("armed");

    // Caller observes the source 30 s after arming; the install
    // delay must be the remaining 90 s, not the full 120 s.
    let later = armed_at + Duration::from_secs(30);
    let transition = auto_lock_timer_transition(false, &src, later);
    assert_eq!(
        transition,
        AutoLockTimerTransition::Install(Duration::from_secs(90))
    );
}

#[test]
fn auto_lock_timer_transition_install_saturates_at_zero_when_now_past_deadline() {
    // If `now` somehow passes `deadline` before the source was
    // installed (e.g. a slow probe), the install duration saturates
    // at `0`: `glib::timeout_add_local` will fire immediately and
    // `evaluate_timer_fire` will then resolve to `Lock`.
    let tmp = secure_tempdir();
    let (mut vault, store) = create_encrypted(&tmp.path().join("vault.bin"), "hunter2");
    vault.set_auto_lock_enabled(true);
    vault.set_auto_lock_timeout_secs(30).unwrap();
    vault.save(&store).unwrap();

    let armed_at = Instant::now();
    let mut src = IdleSource::new();
    src.refresh(armed_at, &vault).expect("armed");

    let way_later = armed_at + Duration::from_secs(120);
    let transition = auto_lock_timer_transition(false, &src, way_later);
    assert_eq!(transition, AutoLockTimerTransition::Install(Duration::ZERO));
}

// ---------------------------------------------------------------------------
// `evaluate_timer_fire` — pure-logic decision for what a
// `glib::timeout_add_local` callback should do when it fires.
// ---------------------------------------------------------------------------

#[test]
fn evaluate_timer_fire_lock_when_expired() {
    // The deadline elapsed by the time the source fired — lock.
    let tmp = secure_tempdir();
    let (mut vault, store) = create_encrypted(&tmp.path().join("vault.bin"), "hunter2");
    vault.set_auto_lock_enabled(true);
    vault.set_auto_lock_timeout_secs(30).unwrap();
    vault.save(&store).unwrap();

    let armed_at = Instant::now();
    let mut src = IdleSource::new();
    src.refresh(armed_at, &vault).expect("armed");

    let fire_at = armed_at + Duration::from_secs(30);
    let decision = evaluate_timer_fire(&src, fire_at);
    assert_eq!(decision, AutoLockFireDecision::Lock);
}

#[test]
fn evaluate_timer_fire_reschedule_when_armed_in_future() {
    // The deadline got pushed forward by an idle event after the
    // source was scheduled; the early fire resolves to a
    // `Reschedule(remaining)` so the caller installs a fresh
    // one-shot for the new deadline.
    let tmp = secure_tempdir();
    let (mut vault, store) = create_encrypted(&tmp.path().join("vault.bin"), "hunter2");
    vault.set_auto_lock_enabled(true);
    vault.set_auto_lock_timeout_secs(300).unwrap();
    vault.save(&store).unwrap();

    let armed_at = Instant::now();
    let mut src = IdleSource::new();
    src.refresh(armed_at, &vault).expect("armed");

    // Fire happens 100 s in — 200 s of deadline remain.
    let fire_at = armed_at + Duration::from_secs(100);
    let decision = evaluate_timer_fire(&src, fire_at);
    assert_eq!(
        decision,
        AutoLockFireDecision::Reschedule(Duration::from_secs(200))
    );
}

#[test]
fn evaluate_timer_fire_cancel_when_disarmed() {
    // Source was disarmed after install (e.g. user toggled off
    // auto-lock, or the vault dropped to plaintext through a
    // passphrase transition) — the in-flight callback resolves to
    // `Cancel` rather than `Lock` so the user does not get locked
    // out by a stale timer.
    let src = IdleSource::new();
    let decision = evaluate_timer_fire(&src, Instant::now());
    assert_eq!(decision, AutoLockFireDecision::Cancel);
}
