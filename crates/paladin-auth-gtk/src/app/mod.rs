// SPDX-License-Identifier: AGPL-3.0-or-later

//! `AppModel`-level glue for `paladin-auth-gtk`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" and
//! §"Vault interaction", `AppModel` owns the resolved vault path
//! plus one of the `Missing`, `Locked`, `Unlocked`, `UnlockedBusy`,
//! or `StartupError` states, and routes startup outcomes from
//! `paladin_auth_core::default_vault_path()` and `paladin_auth_core::inspect(path)`
//! onto that state machine. The pure-logic shadow lives in
//! [`state`] so the routing and transition rules are exercised by
//! `tests/app_state_logic.rs` without a display server or a real
//! `(Vault, Store)` pair.
//!
//! The widget-bearing relm4 component lives in [`model`]; this
//! skeleton stage mounts an empty `adw::ApplicationWindow` and
//! respects the hidden `--exit-after-startup` smoke-test flag. The
//! startup probes that drive routing and the per-`AppState` child
//! views (`InitDialog`, `UnlockComponent`, `AccountListComponent`,
//! …) land in subsequent commits without churning the test-side
//! imports.

pub mod model;
pub mod state;
