// SPDX-License-Identifier: AGPL-3.0-or-later
//
// `policy::auto_lock::IdlePolicy` — auto-lock idle-deadline math
// shared by the TUI and the GTK GUI (DESIGN.md §6 / §7).
//
// Encrypted-only gating: a plaintext vault never arms the auto-lock
// timer regardless of the user's `auto_lock.enabled` setting, since
// "lock" has no meaning without an encryption key to drop. This rule
// lives here, not in the front ends, so the TUI and GUI cannot drift.

use std::time::{Duration, Instant};

use crate::storage::VaultSettings;

/// Auto-lock idle-deadline policy (DESIGN.md §4.7 / §6 / §7).
///
/// Stateless: every method takes the inputs it needs, so the same
/// policy serves both presentation crates without sharing mutable
/// state.
pub struct IdlePolicy;

impl IdlePolicy {
    /// Whether the auto-lock timer should be armed at all.
    ///
    /// Returns `true` iff the vault is encrypted **and** the user has
    /// opted into auto-lock via `VaultSettings::auto_lock_enabled`.
    /// Plaintext vaults always return `false` per the §6 / §7
    /// plaintext no-op rule.
    #[must_use]
    pub fn should_arm(is_encrypted: bool, settings: &VaultSettings) -> bool {
        is_encrypted && settings.auto_lock_enabled()
    }

    /// Compute the next auto-lock deadline relative to `now`.
    ///
    /// Returns `Some(now + Duration::from_secs(timeout_secs))` when
    /// [`Self::should_arm`] is true, otherwise `None`. The bound on
    /// `auto_lock_timeout_secs` (`AUTO_LOCK_SECS_MIN..=AUTO_LOCK_SECS_MAX`,
    /// at most 24 h) keeps the addition safely inside `Instant`'s
    /// representable range on every supported platform.
    #[must_use]
    pub fn next_deadline(
        now: Instant,
        is_encrypted: bool,
        settings: &VaultSettings,
    ) -> Option<Instant> {
        if Self::should_arm(is_encrypted, settings) {
            Some(now + Duration::from_secs(u64::from(settings.auto_lock_timeout_secs())))
        } else {
            None
        }
    }

    /// Whether the deadline has expired by the time `now` was sampled.
    ///
    /// Uses a strict monotonic comparison `now >= deadline` so a tick
    /// that lands exactly on the deadline fires the lock; both inputs
    /// come from the same monotonic `Instant` clock, so wall-clock
    /// drift cannot perturb the comparison.
    #[must_use]
    pub fn is_expired(deadline: Instant, now: Instant) -> bool {
        now >= deadline
    }
}
