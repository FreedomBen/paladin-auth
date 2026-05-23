// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Import-flow types (docs/DESIGN.md §4.6 / §4.7 / §5):
//   - `ImportConflict` — Skip / Replace / Append merge policy passed
//     to `Vault::import_accounts`.
//   - `ImportWarning` — a `ValidationWarning` paired with the
//     zero-based source-row index it came from.
//   - `ImportReport` — counts, the IDs of every imported / replaced /
//     appended row, and the warnings collected before the merge
//     policy was applied.
//
// Format-specific importers (Phase I) build `Vec<ValidatedAccount>`
// and call `Vault::import_accounts`; this module only owns the
// merge-flow value types.

use crate::domain::AccountId;
use crate::ValidationWarning;

/// Per-batch merge policy applied by `Vault::import_accounts` when an
/// incoming row collides with an existing account by the exact
/// `(secret, issuer, label)` triple.
///
/// - `Skip` keeps the existing entry; the colliding source row is
///   counted under `skipped` and is **not** added to
///   `ImportReport.accounts`.
/// - `Replace` overwrites the existing entry, preserving its `id`
///   and `created_at`, setting `updated_at = import_time`, and (for
///   HOTP-to-HOTP collisions) preserving the existing
///   `Hotp.counter`. Cross-kind replacements swap the whole `kind`.
/// - `Append` inserts the colliding row as an additional account
///   with a fresh `AccountId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "error-serde", derive(serde::Serialize))]
#[cfg_attr(feature = "error-serde", serde(rename_all = "snake_case"))]
pub enum ImportConflict {
    /// Keep the existing entry; the colliding source row is counted under `skipped`.
    Skip,
    /// Overwrite the existing entry, preserving `id`, `created_at`, and HOTP counter.
    Replace,
    /// Insert the colliding row as an additional account with a fresh `AccountId`.
    Append,
}

/// A non-fatal `ValidationWarning` paired with its zero-based source
/// position in the original `Vec<ValidatedAccount>`.
///
/// Warnings are collected **before** the merge policy is applied, so a
/// short-secret warning on a row that is later skipped under
/// `ImportConflict::Skip` is still surfaced to the front end.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "error-serde", derive(serde::Serialize))]
pub struct ImportWarning {
    /// 0-based index of the warning's source row in the original input batch.
    pub source_index: usize,
    /// The non-fatal validation warning attached to that row.
    #[cfg_attr(feature = "error-serde", serde(flatten))]
    pub warning: ValidationWarning,
}

/// Outcome of a `Vault::import_accounts` call (docs/DESIGN.md §4.7 / §5).
///
/// The four counts always partition the input: every source row is
/// accounted for exactly once across `imported`, `skipped`,
/// `replaced`, and `appended`. `accounts` lists the resulting vault
/// IDs of every row that produced or modified an entry — i.e. the
/// union of the imported / replaced / appended rows, in source
/// order — so callers can format an `AccountSummary` list without
/// re-scanning the vault.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "error-serde", derive(serde::Serialize))]
pub struct ImportReport {
    /// Number of source rows added as new accounts (no collision).
    pub imported: usize,
    /// Number of source rows skipped under [`ImportConflict::Skip`].
    pub skipped: usize,
    /// Number of source rows that overwrote an existing account under [`ImportConflict::Replace`].
    pub replaced: usize,
    /// Number of source rows appended as fresh accounts under [`ImportConflict::Append`].
    pub appended: usize,
    /// Vault IDs of every row that produced or modified an entry, in source order.
    pub accounts: Vec<AccountId>,
    /// Non-fatal warnings collected before the merge policy was applied.
    pub warnings: Vec<ImportWarning>,
}
