// SPDX-License-Identifier: AGPL-3.0-or-later

//! Command dispatch modules. Each submodule implements the body of one
//! `paladin` subcommand documented in docs/DESIGN.md §5; bodies are stubbed in
//! the initial scaffold and filled in by subsequent commits per
//! `docs/IMPLEMENTATION_PLAN_02_CLI.md`.

pub mod add;
pub mod copy;
pub mod export;
pub mod import;
pub mod init;
pub mod list;
pub mod passphrase;
pub mod peek;
pub mod qr;
pub mod remove;
pub mod rename;
pub mod settings;
pub mod show;
