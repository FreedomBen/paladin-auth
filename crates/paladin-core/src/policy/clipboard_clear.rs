// SPDX-License-Identifier: AGPL-3.0-or-later
//
// `policy::clipboard_clear::ClipboardClearPolicy` — wipe-after-copy
// scheduling and only-if-unchanged byte-equality decision shared by
// the TUI and the GTK GUI (docs/DESIGN.md §6 / §7).
//
// Front ends own the OS clipboard surface (`arboard`,
// `gdk::Clipboard`); the policy module owns the schedule decision,
// monotonic token issuance, and the only-if-unchanged byte-equality
// decision so both presentation crates drive their clipboards with
// identical semantics. The CLI is stateless (docs/DESIGN.md §6) and
// ignores `clipboard.clear_enabled` entirely; this policy is opt-in
// for TUI / GUI only.
//
// Unlike `auto_lock::IdlePolicy`, clipboard auto-clear does **not**
// gate on encryption mode — wiping a copied OTP is useful for both
// plaintext and encrypted vaults. The §6 / §7 plaintext no-op rule
// applies to "lock", not to "wipe clipboard".

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::storage::VaultSettings;

/// Monotonic token issued by [`ClipboardClearPolicy::schedule`].
///
/// Each successful schedule call yields a token strictly greater than
/// the previous one. A deferred wipe captures the token at copy time
/// and compares it to the policy's current token to detect whether a
/// later copy has superseded it: token equality means "still the
/// freshest copy", token inequality means "stale, do not wipe".
///
/// Tokens are `Copy`, so callers pass them by value freely.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct ClipboardClearToken(u64);

impl ClipboardClearToken {
    /// The next token in the issuance sequence. Pure — does not
    /// touch the global counter. The Phase G.19 contract guarantees
    /// `token_n.successor() == token_{n+1}` when no other call to
    /// [`ClipboardClearPolicy::schedule`] interleaves between them.
    ///
    /// Wraparound at `u64::MAX` is unreachable in any realistic
    /// process lifetime; using `wrapping_add` avoids an unreachable
    /// panic path.
    #[must_use]
    pub fn successor(self) -> Self {
        Self(self.0.wrapping_add(1))
    }
}

/// Process-wide monotonic token counter. Each `fetch_add` is
/// atomic, so per-call monotonicity holds across threads;
/// `Relaxed` ordering is sufficient because the token value alone
/// carries the comparison semantics.
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(0);

/// Clipboard wipe-after-copy policy (docs/DESIGN.md §4.7 / §6 / §7).
///
/// Stateless: every method takes the inputs it needs, so the same
/// policy serves both presentation crates without sharing mutable
/// state.
pub struct ClipboardClearPolicy;

impl ClipboardClearPolicy {
    /// Schedule a wipe-after-copy when the user has opted in.
    ///
    /// Returns `Some((token, deadline))` with
    /// `deadline == now + Duration::from_secs(settings.clipboard_clear_secs())`
    /// when [`VaultSettings::clipboard_clear_enabled`] is true,
    /// otherwise `None`. A `None` return does **not** advance the
    /// token counter, so token issuance stays strictly contiguous
    /// across enable / disable transitions.
    ///
    /// `clipboard_clear_secs` is bounded `5..=600` (DESIGN §5), so
    /// the deadline addition stays within `Instant`'s representable
    /// range on every supported platform.
    #[must_use]
    pub fn schedule(
        now: Instant,
        settings: &VaultSettings,
    ) -> Option<(ClipboardClearToken, Instant)> {
        if !settings.clipboard_clear_enabled() {
            return None;
        }
        let token = ClipboardClearToken(NEXT_TOKEN.fetch_add(1, Ordering::Relaxed));
        let deadline = now + Duration::from_secs(u64::from(settings.clipboard_clear_secs()));
        Some((token, deadline))
    }

    /// Whether the deferred wipe should fire: `true` iff the bytes
    /// currently in the clipboard still byte-equal the bytes the
    /// front end captured when it wrote the secret.
    ///
    /// A user who copies something else in the interim leaves a
    /// non-matching `current`, and the wipe stays its hand. The
    /// comparison is plain byte equality, not constant time — the
    /// revealed OTP code is already public, and the policy never
    /// sees the user's other clipboard contents.
    #[must_use]
    pub fn should_clear(captured: &[u8], current: &[u8]) -> bool {
        captured == current
    }
}
