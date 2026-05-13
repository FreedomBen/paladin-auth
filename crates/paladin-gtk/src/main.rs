// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin-gtk` binary entry point.
//!
//! Defers to [`paladin_gtk::run`] so the library surface owns argv
//! parsing and the relm4 / libadwaita bootstrap. See
//! `IMPLEMENTATION_PLAN_04_GTK.md` §"Crate layout".

use std::process::ExitCode;

fn main() -> ExitCode {
    paladin_gtk::run()
}
