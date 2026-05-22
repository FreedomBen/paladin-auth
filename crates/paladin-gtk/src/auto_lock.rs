// SPDX-License-Identifier: AGPL-3.0-or-later

//! Auto-lock pure-logic glue for `paladin-gtk`.
//!
//! Per `IMPLEMENTATION_PLAN_04_GTK.md`
//! §"Auto-lock and clipboard auto-clear (per §7)" and the §"Tests >
//! Pure-logic unit tests > `tests/auto_lock_logic.rs`" checklist, the
//! GUI owns the idle-event sourcing (`gtk::EventControllerKey`, motion
//! controllers, `glib::timeout_add_local`) but routes every policy
//! decision through [`paladin_core::policy::auto_lock::IdlePolicy`]:
//! encrypted-only gating, idle next-deadline arithmetic, and monotonic
//! expiry comparison.
//!
//! This module is the *only* place in `paladin-gtk` that converts a
//! [`Vault`] handle into an `IdlePolicy` input pair (`is_encrypted`,
//! `settings`), so the plaintext-no-op rule (DESIGN §6 / §7) cannot
//! drift into a GUI shortcut.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use paladin_core::policy::auto_lock::IdlePolicy;
use paladin_core::{Store, Vault};

use crate::clipboard_clear::PendingClipboardClear;

/// Compute the next auto-lock deadline relative to `now` for the
/// currently-unlocked `vault`.
///
/// Routes through
/// [`IdlePolicy::next_deadline`][paladin_core::policy::auto_lock::IdlePolicy::next_deadline],
/// passing [`Vault::is_encrypted`] and [`Vault::settings`]. Plaintext
/// vaults return `None` regardless of the user's `auto_lock_enabled`
/// setting because the §6 / §7 plaintext-no-op rule lives in core.
#[must_use]
pub fn idle_event_deadline(now: Instant, vault: &Vault) -> Option<Instant> {
    IdlePolicy::next_deadline(now, vault.is_encrypted(), vault.settings())
}

/// Whether the auto-lock timer should be armed at all for the
/// currently-unlocked `vault`.
///
/// Routes through
/// [`IdlePolicy::should_arm`][paladin_core::policy::auto_lock::IdlePolicy::should_arm].
/// The §"Auto-lock and clipboard auto-clear" guidance asks this
/// **after** any successful `PassphraseDialog` transition so the timer
/// state tracks the on-disk vault mode without re-inspecting the file.
#[must_use]
pub fn idle_should_arm(vault: &Vault) -> bool {
    IdlePolicy::should_arm(vault.is_encrypted(), vault.settings())
}

/// Refresh the auto-lock [`IdleSource`] against a post-`PassphraseDialog`
/// vault state, gated on a successful transition.
///
/// Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Clipboard + auto-lock parity
/// with TUI" — "Re-ask `IdlePolicy::should_arm` after every successful
/// `PassphraseDialog` transition so arm/disarm tracks the on-disk vault
/// mode without re-inspecting the file." The arm/disarm decision is
/// surfaced as `Some` / `None` on the deadline that
/// [`IdleSource::refresh`] (and therefore
/// [`IdlePolicy::next_deadline`][paladin_core::policy::auto_lock::IdlePolicy::next_deadline])
/// returns, so consulting [`IdlePolicy::should_arm`] is a strict subset
/// of refreshing the source.
///
/// `new_is_encrypted` carries the typed
/// [`PassphraseDispatch::new_is_encrypted`][crate::app::state::PassphraseDispatch::new_is_encrypted]
/// projection from
/// [`compose_passphrase_dispatch`][crate::app::state::compose_passphrase_dispatch]:
///
/// * `Some(_)` — success branch (any of `set` / `change` / `remove`).
///   Refreshes the source against the reinstalled `vault` so the new
///   on-disk mode and the user's `auto_lock_enabled` setting both feed
///   into the policy decision.
/// * `None` — failure branch. DESIGN §4.5 owns the in-memory rollback
///   / replacement and the dialog stays open, so no re-arm decision is
///   taken and the source is left bit-identical.
///
/// Returns `true` iff the source was refreshed.
#[must_use]
pub fn refresh_idle_source_after_passphrase(
    idle_source: &mut IdleSource,
    new_is_encrypted: Option<bool>,
    vault: &Vault,
    now: Instant,
) -> bool {
    if new_is_encrypted.is_some() {
        idle_source.refresh(now, vault);
        true
    } else {
        false
    }
}

/// Strict monotonic deadline check, exposed here so callers don't
/// need to import the policy directly.
///
/// Routes through
/// [`IdlePolicy::is_expired`][paladin_core::policy::auto_lock::IdlePolicy::is_expired].
/// `now >= deadline` fires the lock; both inputs come from the same
/// monotonic [`Instant`] clock used elsewhere in the GUI.
#[must_use]
pub fn is_expired(deadline: Instant, now: Instant) -> bool {
    IdlePolicy::is_expired(deadline, now)
}

/// Bundle of `AppModel::Unlocked` fields that the auto-lock expiry
/// transition MUST discard.
///
/// Generic over the HOTP-reveal and modal payload types so this
/// module stays pure-logic (no `gtk::Widget` / relm4 component
/// dependencies). The reducer / component layer instantiates the
/// generics with its concrete reveal-window and dialog state types.
///
/// Per the §"Tests > `tests/auto_lock_logic.rs`" checklist, the
/// search query, any open HOTP reveal window, and any open dialog are
/// all dropped on auto-lock.
pub struct UnlockedDiscards<Reveal, Modal> {
    /// The live search-bar query — cleared on lock.
    pub search_query: String,
    /// Any open HOTP reveal window — closed on lock.
    pub hotp_reveal: Option<Reveal>,
    /// Any open modal dialog — closed on lock.
    pub modal: Option<Modal>,
}

/// The `AppModel::Locked` snapshot produced by an auto-lock expiry
/// transition.
///
/// The vault path survives the lock; the open `Vault`, `Store`,
/// search query, HOTP reveal window, and any open dialog are dropped
/// by [`lock_on_expiry`] via move semantics. A pending clipboard
/// auto-clear scheduled before the lock survives so its timer still
/// fires only-if-unchanged on the post-lock clipboard — per
/// `IMPLEMENTATION_PLAN_04_GTK.md` §"Tests > `tests/clipboard_clear_logic.rs`"
/// *"A clipboard auto-clear timer scheduled before lock survives lock
/// and still fires only-if-unchanged."*
pub struct LockedTransition {
    /// The resolved vault path. `UnlockComponent` re-presents against
    /// this path after lock.
    pub path: PathBuf,
    /// Pending clipboard wipe-after-copy entry, carried forward
    /// across the auto-lock transition so the deferred wake still
    /// finds state to act on. `None` when no clipboard auto-clear
    /// was scheduled at lock time, or when the user has not opted in.
    pub pending_clipboard_clear: Option<PendingClipboardClear>,
}

/// Build a [`LockedTransition`] from an expired `AppModel::Unlocked`
/// state.
///
/// Takes `vault`, `store`, and `discards` **by value** so the caller
/// cannot smuggle them past the lock. `pending_clipboard_clear` is
/// carried forward verbatim so a clipboard timer scheduled before
/// lock still fires only-if-unchanged after lock.
#[must_use]
pub fn lock_on_expiry<Reveal, Modal>(
    path: PathBuf,
    _vault: Vault,
    _store: Store,
    _discards: UnlockedDiscards<Reveal, Modal>,
    pending_clipboard_clear: Option<PendingClipboardClear>,
) -> LockedTransition {
    LockedTransition {
        path,
        pending_clipboard_clear,
    }
}

/// The GTK side's record of the currently armed auto-lock deadline.
///
/// `AppModel` owns one [`IdleSource`] for the lifetime of the app.
/// Every `gtk::EventControllerKey` / `gtk::EventControllerMotion`
/// event refreshes the deadline through [`Self::refresh`], which
/// routes the arm decision through
/// [`IdlePolicy`][paladin_core::policy::auto_lock::IdlePolicy]: the
/// plaintext-no-op rule and the opt-in
/// [`VaultSettings::auto_lock_enabled`][paladin_core::VaultSettings::auto_lock_enabled]
/// gate live in core, so the wiring side cannot drift.
///
/// The source is stateful purely so the GUI has one place to read
/// "current deadline" (the timer needs it to schedule
/// `glib::timeout_add_local` in a follow-up sub-task) and one place
/// to clear it on lock / quit / vault drop. The actual policy math
/// is delegated to `IdlePolicy` on every refresh.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct IdleSource {
    deadline: Option<Instant>,
}

impl IdleSource {
    /// Build a fresh, disarmed source. Equivalent to
    /// [`IdleSource::default`].
    #[must_use]
    pub fn new() -> Self {
        Self { deadline: None }
    }

    /// Current armed deadline, or `None` when disarmed.
    #[must_use]
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// Whether an armed deadline is currently held.
    #[must_use]
    pub fn is_armed(&self) -> bool {
        self.deadline.is_some()
    }

    /// Refresh the deadline relative to `now` against the live
    /// `vault`.
    ///
    /// Routes through [`idle_event_deadline`] (and therefore
    /// [`IdlePolicy::next_deadline`][paladin_core::policy::auto_lock::IdlePolicy::next_deadline]),
    /// so plaintext vaults disarm regardless of the user's
    /// `auto_lock_enabled` setting and encrypted vaults with the
    /// setting disabled also disarm. Returns the new deadline.
    ///
    /// Calling this on every idle event (key press / pointer
    /// motion) pushes the deadline forward by exactly
    /// `auto_lock_timeout_secs`, so a busy user keeps the timer
    /// rolling and an idle one trips it.
    pub fn refresh(&mut self, now: Instant, vault: &Vault) -> Option<Instant> {
        self.deadline = idle_event_deadline(now, vault);
        self.deadline
    }

    /// Whether the armed deadline has elapsed by `now`.
    ///
    /// Routes through [`is_expired`][crate::auto_lock::is_expired]
    /// (and therefore
    /// [`IdlePolicy::is_expired`][paladin_core::policy::auto_lock::IdlePolicy::is_expired]).
    /// A disarmed source never reports expiry — the timer must not
    /// fire while plaintext or opted-out.
    #[must_use]
    pub fn is_expired(&self, now: Instant) -> bool {
        self.deadline.is_some_and(|d| is_expired(d, now))
    }

    /// Clear the deadline. Used on lock, quit, and vault drop.
    pub fn disarm(&mut self) {
        self.deadline = None;
    }
}

/// Lifecycle transition the auto-lock `glib::timeout_add_local` driver
/// should apply when the `(was_installed, idle_source)` pair changes.
///
/// Mirrors [`crate::ticker::TickerTransition`]'s typed-decision shape
/// so the widget layer's install / teardown call sites are exhaustive
/// against the four cells of the truth table and cannot thrash the
/// source by ignoring a no-op transition. The
/// [`IdlePolicy`][paladin_core::policy::auto_lock::IdlePolicy]
/// arm/disarm decision lives in core; this enum is the pure-logic
/// glue between [`IdleSource::is_armed`] and the GTK timeout source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoLockTimerTransition {
    /// No change — the source is already in the right state for the
    /// current `(was_installed, idle_source)` pair. The widget layer
    /// makes no `glib::timeout_add_local` / `glib::source_remove`
    /// calls.
    NoChange,
    /// Install a fresh `glib::timeout_add_local` one-shot source at
    /// the carried [`Duration`] (computed as
    /// `deadline.saturating_duration_since(now)` so a slow probe past
    /// the deadline still saturates at zero rather than wrapping).
    Install(Duration),
    /// Tear down the existing `glib::timeout_add_local` source. Used
    /// on lock, quit, and any transition that disarms the source
    /// (plaintext / opted-out / passphrase removal).
    Teardown,
}

/// Collapse the `(was_installed, idle_source.is_armed())` matrix into
/// a single [`AutoLockTimerTransition`] outcome.
///
/// The four outcomes:
///
/// | `was_installed` | `idle_source.is_armed()` | result                |
/// |-----------------|--------------------------|-----------------------|
/// | `false`         | `true`                   | `Install(remaining)`  |
/// | `true`          | `false`                  | `Teardown`            |
/// | `true`          | `true`                   | `NoChange`            |
/// | `false`         | `false`                  | `NoChange`            |
///
/// The `NoChange` cell for an armed source plus an installed source
/// is deliberate: the existing one-shot will fire and
/// [`evaluate_timer_fire`] will resolve to `Reschedule` if the
/// deadline got pushed forward in the interim. That avoids a
/// `glib::source_remove` + `glib::timeout_add_local` round trip on
/// every key press.
///
/// The `Install` duration is `deadline.saturating_duration_since(now)`
/// so a `now` past the deadline produces `Duration::ZERO`; the source
/// fires immediately and [`evaluate_timer_fire`] resolves to `Lock`.
#[must_use]
pub fn auto_lock_timer_transition(
    was_installed: bool,
    idle_source: &IdleSource,
    now: Instant,
) -> AutoLockTimerTransition {
    match (was_installed, idle_source.deadline()) {
        (true, None) => AutoLockTimerTransition::Teardown,
        (false, Some(deadline)) => {
            AutoLockTimerTransition::Install(deadline.saturating_duration_since(now))
        }
        (false, None) | (true, Some(_)) => AutoLockTimerTransition::NoChange,
    }
}

/// Pure-logic decision for what an auto-lock
/// `glib::timeout_add_local` callback should do when it fires.
///
/// `Lock` triggers the §"Auto-lock and clipboard auto-clear" expiry
/// transition — the model drops `Vault`, switches `AppModel` to
/// `Locked`, discards open HOTP reveal windows, the search query, and
/// any open dialog, then re-presents `UnlockComponent`.
/// `Reschedule(remaining)` installs a fresh one-shot for the new
/// deadline (the previous source must have fired early because the
/// deadline got pushed forward by an idle event after install).
/// `Cancel` drops the timer without locking (source was disarmed
/// after install — e.g. a passphrase transition replaced the vault
/// with a plaintext one, or the user toggled auto-lock off).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoLockFireDecision {
    /// Lock the vault — the source's deadline elapsed by `now`.
    Lock,
    /// Source is still armed but the deadline is in the future.
    /// Install a fresh one-shot at the carried [`Duration`].
    Reschedule(Duration),
    /// Source is disarmed; drop the fired timer without locking.
    Cancel,
}

/// Resolve a fired auto-lock timer against the current
/// [`IdleSource`] state.
///
/// The fire handler in `AppModel` consumes the returned
/// [`AutoLockFireDecision`] to either lock the vault, reschedule a
/// fresh one-shot for the new deadline, or drop the timer without
/// locking. The decision routes the expiry check through
/// [`IdleSource::is_expired`] (and therefore
/// [`IdlePolicy::is_expired`][paladin_core::policy::auto_lock::IdlePolicy::is_expired])
/// so the monotonic comparison lives in core.
#[must_use]
pub fn evaluate_timer_fire(idle_source: &IdleSource, now: Instant) -> AutoLockFireDecision {
    match idle_source.deadline() {
        None => AutoLockFireDecision::Cancel,
        Some(deadline) if is_expired(deadline, now) => AutoLockFireDecision::Lock,
        Some(deadline) => AutoLockFireDecision::Reschedule(deadline.saturating_duration_since(now)),
    }
}
