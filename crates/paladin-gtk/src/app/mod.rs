// SPDX-License-Identifier: AGPL-3.0-or-later

//! `AppModel`-level glue for `paladin-gtk`.
//!
//! Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" and
//! §"Vault interaction", `AppModel` owns the resolved vault path
//! plus one of the `Missing`, `Locked`, `Unlocked`, `UnlockedBusy`,
//! or `StartupError` states, and routes startup outcomes from
//! `paladin_core::default_vault_path()` and `paladin_core::inspect(path)`
//! onto that state machine. The pure-logic shadow lives in
//! [`state`] so the routing and transition rules are exercised by
//! `tests/app_state_logic.rs` without a display server or a real
//! `(Vault, Store)` pair.
//!
//! The widget-bearing Relm4 component (`AppModel` itself, plus
//! `AppMsg` / `AppOutput`) lands in a follow-up commit alongside
//! the rest of the §"Component tree" wiring; this module reserves
//! the path layout from the crate-layout block and keeps the pure-
//! logic state machine importable as
//! `paladin_gtk::app::state::AppState` so later commits can extend
//! it without churning the test-side imports.

pub mod state;
