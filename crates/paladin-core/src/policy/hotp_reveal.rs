// SPDX-License-Identifier: AGPL-3.0-or-later
//
// `policy::hotp_reveal::deadline` — HOTP reveal countdown deadline
// shared by the TUI reveal panel and the GTK GUI reveal panel
// (docs/DESIGN.md §6 / §7).
//
// HOTP codes do not roll over on a wall-clock cadence the way TOTP
// does, so the front ends hide the displayed code after a fixed
// reveal horizon (`HOTP_REVEAL_SECS`, pinned by `ui_contract`). Both
// presentation crates source the deadline through this function so a
// future change to the horizon updates them in lockstep.

use std::time::{Duration, Instant};

use crate::ui_contract::HOTP_REVEAL_SECS;

/// Compute the HOTP reveal countdown deadline relative to `now`.
///
/// Returns `now + Duration::from_secs(HOTP_REVEAL_SECS)`. Pure
/// addition: no clock sampling, no shared state, no encryption-mode
/// gating — the front ends decide whether to display the countdown
/// at all, and the policy decides only when it should expire.
#[must_use]
pub fn deadline(now: Instant) -> Instant {
    now + Duration::from_secs(HOTP_REVEAL_SECS)
}
