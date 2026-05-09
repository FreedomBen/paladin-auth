// SPDX-License-Identifier: AGPL-3.0-or-later

//! Thin wrapper around `paladin_core::parse_account_query`,
//! `Vault::matching_accounts`, and `Vault::shortest_unique_id_prefix`. The
//! CLI owns only command-specific cardinality decisions and error rendering;
//! the matching itself stays in core (see `IMPLEMENTATION_PLAN_02_CLI.md`
//! "Query resolution"). Stub; populated as commands land.
