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
use std::time::Instant;

use paladin_core::policy::auto_lock::IdlePolicy;
use paladin_core::{Store, Vault};

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
/// Only the vault path survives the lock; the open `Vault`, `Store`,
/// search query, HOTP reveal window, and any open dialog are
/// dropped by [`lock_on_expiry`] via move semantics.
pub struct LockedTransition {
    /// The resolved vault path. `UnlockComponent` re-presents against
    /// this path after lock.
    pub path: PathBuf,
}

/// Build a [`LockedTransition`] from an expired `AppModel::Unlocked`
/// state.
///
/// Takes `vault`, `store`, and `discards` **by value** so the caller
/// cannot smuggle them past the lock. The returned `LockedTransition`
/// holds only the vault path; everything else is dropped in this
/// function's stack frame.
#[must_use]
pub fn lock_on_expiry<Reveal, Modal>(
    path: PathBuf,
    _vault: Vault,
    _store: Store,
    _discards: UnlockedDiscards<Reveal, Modal>,
) -> LockedTransition {
    LockedTransition { path }
}
