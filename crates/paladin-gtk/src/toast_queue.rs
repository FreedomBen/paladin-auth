// SPDX-License-Identifier: AGPL-3.0-or-later

//! Newest-wins toast collapse queue with a minimum-visible guarantee.
//!
//! The unlocked-vault window shares a single `adw::ToastOverlay`
//! across every code-copy, worker-success, and worker-failure path.
//! Without coordination, back-to-back dispatches (e.g. activating the
//! `Next` cell on a hidden HOTP row fires `ActivateHotpAndCopy`,
//! `HotpAdvanceWorkerCompleted`, and the latched `CopyCode` follow-up
//! in quick succession) would stack toasts in the overlay so the
//! interesting confirmation only surfaces seconds later, behind the
//! intermediate banners.
//!
//! This module owns the pure-logic half of the "newest body wins,
//! never cut a toast short of [`TOAST_MIN_VISIBLE`]" policy. The GTK
//! side (`AppModel::show_toast` / `commit_toast` in
//! `crate::app::model`) owns the live [`adw::Toast`] handle and the
//! `glib::timeout_add_local_once` source; this struct only answers
//! the two questions the imperative side needs:
//!
//! * `on_show(body)` — should the next toast surface to the overlay
//!   right now, or has the prior toast not yet been visible long
//!   enough? When deferred the body is stashed so the newest pending
//!   body wins, matching the user's "don't stack — show the latest"
//!   request.
//! * `on_min_visible_elapsed()` — the [`TOAST_MIN_VISIBLE`] timer the
//!   GTK side started when it committed the prior toast just fired;
//!   drain any pending body so the imperative side can hand it to
//!   the overlay (starting a fresh min-visible window) or report an
//!   idle queue.
//!
//! Keeping the dispatch table here (rather than inside the model's
//! `update` body) means the unit tests can pin the
//! `(active, pending)` transitions without spinning up GTK or an
//! `adw::ToastOverlay`.

use std::time::Duration;

/// Minimum time a toast must remain on the `adw::ToastOverlay`
/// before [`ToastQueue::on_show`] will dismiss it in favor of a
/// newer body. One second is enough that a single back-to-back
/// dispatch storm (copy → durability-unconfirmed → reveal-toast)
/// cannot flash the first body off the screen, but short enough
/// that a deliberate sequence of user actions still feels
/// responsive.
pub const TOAST_MIN_VISIBLE: Duration = Duration::from_millis(1000);

/// Verdict from [`ToastQueue::on_show`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShowAction {
    /// The imperative side should dismiss any stashed
    /// `adw::Toast` it still holds, add a fresh `adw::Toast` for
    /// the supplied body to the overlay, and schedule a
    /// [`TOAST_MIN_VISIBLE`] one-shot that posts back through
    /// `on_min_visible_elapsed`.
    Commit,
    /// The supplied body has been stashed in
    /// [`ToastQueue::pending`]. The imperative side does nothing
    /// here — the next `on_min_visible_elapsed` call will return
    /// the body so it can be committed then.
    Defer,
}

/// Pure-logic state for the toast collapse queue. The
/// imperative side mirrors this with the live [`adw::Toast`]
/// reference and the [`TOAST_MIN_VISIBLE`] timeout source; this
/// struct only tracks the dispatch table.
#[derive(Debug, Default, Clone)]
pub struct ToastQueue {
    /// `true` between the [`ShowAction::Commit`] that started the
    /// most recent toast's min-visible window and the
    /// [`Self::on_min_visible_elapsed`] call that closes it.
    min_visible_active: bool,
    /// Latest toast body queued behind an active min-visible
    /// window. Replaced on each [`Self::on_show`] while
    /// `min_visible_active` is `true` so the newest body always
    /// wins; consumed (and cleared) by
    /// [`Self::on_min_visible_elapsed`].
    pending: Option<String>,
}

impl ToastQueue {
    /// Idle queue: no active min-visible window, no pending body.
    /// Equivalent to [`Self::default`] — provided so call sites read
    /// as `ToastQueue::new()` alongside the other `AppModel`
    /// state-pieces (`IdleSource::new()`, `HashMap::new()`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Drive the queue from the imperative side's `show_toast`
    /// entry. Returns [`ShowAction::Commit`] when the imperative
    /// side should add the body to the overlay immediately (and
    /// start a fresh min-visible timer), or [`ShowAction::Defer`]
    /// when the body has been stashed as the new pending entry.
    pub fn on_show(&mut self, body: String) -> ShowAction {
        if self.min_visible_active {
            self.pending = Some(body);
            ShowAction::Defer
        } else {
            self.min_visible_active = true;
            ShowAction::Commit
        }
    }

    /// Drive the queue from the imperative side's
    /// [`TOAST_MIN_VISIBLE`] timeout firing. Returns `Some(body)`
    /// when a deferred body should now be committed (and a fresh
    /// min-visible window opened), or `None` when no body was
    /// queued and the overlay can sit idle.
    pub fn on_min_visible_elapsed(&mut self) -> Option<String> {
        self.min_visible_active = false;
        let drained = self.pending.take();
        if drained.is_some() {
            self.min_visible_active = true;
        }
        drained
    }

    /// Observability hook for tests / debug-impls. `true` while a
    /// min-visible window is open.
    #[must_use]
    pub fn min_visible_active(&self) -> bool {
        self.min_visible_active
    }

    /// Observability hook for tests / debug-impls. The body that
    /// will surface from the next
    /// [`Self::on_min_visible_elapsed`] call, if any.
    #[must_use]
    pub fn pending(&self) -> Option<&str> {
        self.pending.as_deref()
    }
}
