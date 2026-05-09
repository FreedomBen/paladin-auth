// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared vault-open pipeline used by every read / mutate command except
//! `init`. Implements the `IMPLEMENTATION_PLAN_02_CLI.md` "Vault
//! interaction pattern" steps 1-4: resolve path → `inspect` → optional
//! passphrase prompt → `Store::open`.
//!
//! Per-command cardinality, mutation, and rendering live in the command
//! modules; this helper only owns the open ceremony and its narrow
//! envelope of side effects (the encrypted-mode passphrase prompt).
//!
//! The helper deliberately rejects `Missing` with `vault_missing` and
//! never falls through to `Store::open` with a known-broken file —
//! propagation rules are quoted from the plan.

use std::path::{Path, PathBuf};

use paladin_core::{
    default_vault_path, inspect, PaladinError, Store, Vault, VaultLock, VaultMode, VaultStatus,
};
use secrecy::SecretString;

use crate::cli::GlobalArgs;
use crate::output::error::CliError;
use crate::prompt;

/// Vault opened against the user-resolved path, plus the `Store` handle
/// callers thread back into mutating helpers (`Vault::save`,
/// `hotp_advance`, passphrase transitions).
///
/// `store` / `mode` / `path` are unused by `list` but are part of the
/// shared open contract — `show`, `copy`, mutating commands, and
/// passphrase-transition diagnostics will read them as those landings
/// follow. The `dead_code` allowance is removed once the first
/// consumer lands.
#[allow(dead_code)]
pub struct OpenedVault {
    pub vault: Vault,
    pub store: Store,
    pub mode: VaultMode,
    pub path: PathBuf,
}

/// Resolve the vault path from `--vault` or fall back to
/// `default_vault_path()`.
pub fn resolve_vault_path(global: &GlobalArgs) -> Result<PathBuf, CliError> {
    match &global.vault {
        Some(p) => Ok(p.clone()),
        None => Ok(default_vault_path()?),
    }
}

/// Run the §5 open pipeline against `path` and return the unlocked
/// vault + store.
///
/// `Missing` is mapped to `vault_missing` immediately (no prompt). Any
/// other `inspect` error is propagated verbatim (no prompt). For
/// `Encrypted` vaults the user is prompted once via `/dev/tty`; the
/// resulting `Store::open` call surfaces `invalid_passphrase` for a bad
/// entry and `unsafe_permissions` / `wrong_vault_lock` verbatim.
pub fn open(path: &Path) -> Result<OpenedVault, CliError> {
    let status = inspect(path)?;
    let (lock, mode) = match status {
        VaultStatus::Missing => return Err(CliError::Paladin(PaladinError::VaultMissing)),
        VaultStatus::Plaintext => (VaultLock::Plaintext, VaultMode::Plaintext),
        VaultStatus::Encrypted => {
            let pp: SecretString = prompt::prompt_passphrase("Vault passphrase: ")?;
            (VaultLock::Encrypted(pp), VaultMode::Encrypted)
        }
    };
    let (vault, store) = Store::open(path, lock)?;
    Ok(OpenedVault {
        vault,
        store,
        mode,
        path: path.to_path_buf(),
    })
}
