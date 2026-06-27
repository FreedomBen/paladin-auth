// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared timer math and decision protocols (docs/DESIGN.md §6 / §7).
//!
//! Front ends (TUI and GTK GUI) own raw input handling, OS clipboard
//! adapters, and timer plumbing. The `policy` module owns the
//! state-free decisions both presentation crates need to agree on:
//!
//!   * `auto_lock::IdlePolicy` — encrypted-only gating, idle
//!     next-deadline arithmetic, and monotonic-expiry comparison.
//!   * `clipboard_clear::ClipboardClearPolicy` — schedule decision,
//!     monotonic token issuance, only-if-unchanged byte-equality
//!     decision.
//!   * `hotp_reveal::deadline` — HOTP reveal countdown deadline
//!     pinned to `HOTP_REVEAL_SECS`.
//!
//! Each submodule's public symbols are re-exported at the crate root.

/// Idle auto-lock policy (encrypted-only). See docs/DESIGN.md §6.
pub mod auto_lock;
/// Clipboard-clear scheduling and token issuance. See docs/DESIGN.md §7.
pub mod clipboard_clear;
/// HOTP reveal countdown deadline. See docs/DESIGN.md §4.5.
pub mod hotp_reveal;

pub use auto_lock::IdlePolicy;
pub use clipboard_clear::{ClipboardClearPolicy, ClipboardClearToken};
pub use hotp_reveal::deadline as hotp_reveal_deadline;
