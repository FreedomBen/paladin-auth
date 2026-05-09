// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase J.3 — `Send` posture audit (DESIGN.md §4.7 /
// IMPLEMENTATION_PLAN_01_CORE.md Phase J).
//
// The `paladin-gtk` front end moves vault state across
// `gio::spawn_blocking` boundaries and `paladin-tui` hands import work
// to a worker thread (DESIGN.md §6 / §7). Every public type that
// crosses those boundaries must be `Send` so the move compiles. This
// file gates the full set with `fn assert_send<T: Send>()` calls so a
// future change introducing `Rc` or another `!Send` field fails the
// build instead of silently breaking either binary crate.
//
// The asserted set mirrors the worker-boundary contract enumerated in
// the plan; do not narrow it without updating IMPLEMENTATION_PLAN_01_CORE.md
// Phase J.

use paladin_core::{
    Account, AccountId, AccountInput, AccountKindInput, AccountKindSummary, AccountQuery,
    AccountSummary, Algorithm, Argon2Params, Code, EncryptionOptions, IconHintInput,
    ImportConflict, ImportFormat, ImportOptions, ImportReport, ImportWarning, InitPrecheck,
    PaladinError, PaladinImportPrecheck, SettingKey, SettingPatch, Store, ValidatedAccount,
    ValidationWarning, Vault, VaultInit, VaultLock, VaultSettings, VaultStatus,
};

fn assert_send<T: Send + ?Sized>() {}

// Compile-time gate: instantiating `assert_send::<T>()` for each type
// proves `T: Send` without needing a runtime fixture. If any type loses
// `Send` (e.g. via an `Rc` field), this `const` block fails to compile.
const _: fn() = || {
    assert_send::<Vault>();
    assert_send::<Store>();
    assert_send::<Account>();
    assert_send::<AccountId>();
    assert_send::<AccountSummary>();
    assert_send::<AccountKindSummary>();
    assert_send::<Algorithm>();
    assert_send::<Code>();
    assert_send::<ValidatedAccount>();
    assert_send::<ValidationWarning>();
    assert_send::<ImportReport>();
    assert_send::<ImportWarning>();
    assert_send::<ImportConflict>();
    assert_send::<ImportFormat>();
    assert_send::<ImportOptions>();
    assert_send::<EncryptionOptions>();
    assert_send::<Argon2Params>();
    assert_send::<VaultLock>();
    assert_send::<VaultInit>();
    assert_send::<VaultStatus>();
    assert_send::<VaultSettings>();
    assert_send::<SettingKey>();
    assert_send::<SettingPatch>();
    assert_send::<AccountKindInput>();
    assert_send::<IconHintInput>();
    assert_send::<AccountInput>();
    assert_send::<AccountQuery>();
    assert_send::<InitPrecheck>();
    assert_send::<PaladinImportPrecheck>();
    assert_send::<PaladinError>();
};

#[test]
fn worker_boundary_types_are_send() {
    // Re-asserts the const block above at runtime so the test is
    // visible in `cargo test` output and in CI summaries.
    assert_send::<Vault>();
    assert_send::<Store>();
    assert_send::<Account>();
    assert_send::<AccountId>();
    assert_send::<AccountSummary>();
    assert_send::<AccountKindSummary>();
    assert_send::<Algorithm>();
    assert_send::<Code>();
    assert_send::<ValidatedAccount>();
    assert_send::<ValidationWarning>();
    assert_send::<ImportReport>();
    assert_send::<ImportWarning>();
    assert_send::<ImportConflict>();
    assert_send::<ImportFormat>();
    assert_send::<ImportOptions>();
    assert_send::<EncryptionOptions>();
    assert_send::<Argon2Params>();
    assert_send::<VaultLock>();
    assert_send::<VaultInit>();
    assert_send::<VaultStatus>();
    assert_send::<VaultSettings>();
    assert_send::<SettingKey>();
    assert_send::<SettingPatch>();
    assert_send::<AccountKindInput>();
    assert_send::<IconHintInput>();
    assert_send::<AccountInput>();
    assert_send::<AccountQuery>();
    assert_send::<InitPrecheck>();
    assert_send::<PaladinImportPrecheck>();
    assert_send::<PaladinError>();
}
