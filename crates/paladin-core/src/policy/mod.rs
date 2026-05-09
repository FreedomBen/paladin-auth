// SPDX-License-Identifier: AGPL-3.0-or-later
//
// `policy` — shared timer math and decision protocols (DESIGN.md §6 / §7).
//
// Front ends (TUI and GTK GUI) own raw input handling, OS clipboard
// adapters, and timer plumbing. The `policy` module owns the
// state-free decisions both presentation crates need to agree on:
//
//   * `auto_lock::IdlePolicy` — encrypted-only gating, idle
//     next-deadline arithmetic, and monotonic-expiry comparison.
//   * `clipboard_clear::ClipboardClearPolicy` — schedule decision,
//     monotonic token issuance, only-if-unchanged byte-equality
//     decision (later phase).
//   * `hotp_reveal::deadline` — HOTP reveal countdown deadline
//     (later phase).
//
// Each submodule's public symbols are re-exported at the crate root.

pub mod auto_lock;

pub use auto_lock::IdlePolicy;
