// SPDX-License-Identifier: AGPL-3.0-or-later

//! Output renderers. `text` produces human-facing output that honors
//! `--no-color`, `NO_COLOR`, and TTY detection; `json` produces the stable
//! envelope schema documented in DESIGN.md §5. Filled in by subsequent
//! commits — see `IMPLEMENTATION_PLAN_02_CLI.md` "Output".

pub mod json;
pub mod text;
