// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase J.3 / J.4 — `Send` and `Sync` posture audit (docs/DESIGN.md §4.7 /
// docs/IMPLEMENTATION_PLAN_01_CORE.md Phase J).
//
// J.3 — Send. The `paladin-gtk` front end moves vault state across
// `gio::spawn_blocking` boundaries and `paladin-tui` hands import work
// to a worker thread (docs/DESIGN.md §6 / §7). Every public type that
// crosses those boundaries must be `Send` so the move compiles. This
// file gates the full set with `fn assert_send<T: Send>()` calls so a
// future change introducing `Rc` or another `!Send` field fails the
// build instead of silently breaking either binary crate.
//
// J.4 — Sync. Of the same worker-boundary set, every type *except*
// `Store` is `Sync`. `Store` is `!Sync` because it carries
// `Cell<VaultMode>` and `Cell<Option<EncryptedSaveContext>>` for
// in-place save-pipeline state (docs/DESIGN.md §4.3) and `Cell<T>: !Sync`
// by definition. The remaining secret-bearing types (`Vault`,
// `Account`, `Secret`, `EncryptionOptions`, `AccountInput`,
// `ValidatedAccount`, `VaultLock`, `VaultInit`, `PaladinError`) are
// `Sync` because `secrecy::SecretString` (this crate's only
// secret-storage primitive) is `Sync` in `secrecy = "0.10"` —
// `SecretBox<String>` is `Sync` whenever `String: Sync`, and zeroize
// semantics fire on drop, not on read. Promoting any of those types
// to `!Sync` (or demoting `Store` to `Sync`) would break the cargo
// public-api snapshot in CI and require an explicit review.
//
// The asserted set mirrors the worker-boundary contract enumerated in
// the plan; do not narrow it without updating docs/IMPLEMENTATION_PLAN_01_CORE.md
// Phase J.

use paladin_core::{
    Account, AccountId, AccountInput, AccountKindInput, AccountKindSummary, AccountQuery,
    AccountSummary, Algorithm, Argon2Params, Code, EncryptionOptions, IconHintInput,
    ImportConflict, ImportFormat, ImportOptions, ImportReport, ImportWarning, InitPrecheck,
    PaladinError, PaladinImportPrecheck, SettingKey, SettingPatch, Store, ValidatedAccount,
    ValidationWarning, Vault, VaultInit, VaultLock, VaultSettings, VaultStatus,
};
use static_assertions::assert_not_impl_all;

fn assert_send<T: Send + ?Sized>() {}
fn assert_sync<T: Sync + ?Sized>() {}

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

// Compile-time gate for the Sync posture (J.4). Identical pattern to
// the Send block above — instantiating `assert_sync::<T>()` proves
// `T: Sync` at compile time.
const _: fn() = || {
    assert_sync::<Vault>();
    assert_sync::<Account>();
    assert_sync::<AccountId>();
    assert_sync::<AccountSummary>();
    assert_sync::<AccountKindSummary>();
    assert_sync::<Algorithm>();
    assert_sync::<Code>();
    assert_sync::<ValidatedAccount>();
    assert_sync::<ValidationWarning>();
    assert_sync::<ImportReport>();
    assert_sync::<ImportWarning>();
    assert_sync::<ImportConflict>();
    assert_sync::<ImportFormat>();
    assert_sync::<ImportOptions>();
    assert_sync::<EncryptionOptions>();
    assert_sync::<Argon2Params>();
    assert_sync::<VaultLock>();
    assert_sync::<VaultInit>();
    assert_sync::<VaultStatus>();
    assert_sync::<VaultSettings>();
    assert_sync::<SettingKey>();
    assert_sync::<SettingPatch>();
    assert_sync::<AccountKindInput>();
    assert_sync::<IconHintInput>();
    assert_sync::<AccountInput>();
    assert_sync::<AccountQuery>();
    assert_sync::<InitPrecheck>();
    assert_sync::<PaladinImportPrecheck>();
    assert_sync::<PaladinError>();
};

// Negative assertion: `Store` carries `Cell<...>` fields for the save
// pipeline (docs/DESIGN.md §4.3) and is therefore `!Sync` by construction.
// Pinning this lets a future refactor that removes the `Cell`s — for
// example, by switching to `&mut self` everywhere — show up in CI as
// a deliberate posture change rather than a silent loosening.
assert_not_impl_all!(Store: Sync);

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

#[test]
fn worker_boundary_types_are_sync_except_store() {
    // Re-asserts the Sync const block above at runtime. `Store` is
    // intentionally absent — its negative `!Sync` assertion lives in
    // `assert_not_impl_all!` above and is checked at compile time.
    assert_sync::<Vault>();
    assert_sync::<Account>();
    assert_sync::<AccountId>();
    assert_sync::<AccountSummary>();
    assert_sync::<AccountKindSummary>();
    assert_sync::<Algorithm>();
    assert_sync::<Code>();
    assert_sync::<ValidatedAccount>();
    assert_sync::<ValidationWarning>();
    assert_sync::<ImportReport>();
    assert_sync::<ImportWarning>();
    assert_sync::<ImportConflict>();
    assert_sync::<ImportFormat>();
    assert_sync::<ImportOptions>();
    assert_sync::<EncryptionOptions>();
    assert_sync::<Argon2Params>();
    assert_sync::<VaultLock>();
    assert_sync::<VaultInit>();
    assert_sync::<VaultStatus>();
    assert_sync::<VaultSettings>();
    assert_sync::<SettingKey>();
    assert_sync::<SettingPatch>();
    assert_sync::<AccountKindInput>();
    assert_sync::<IconHintInput>();
    assert_sync::<AccountInput>();
    assert_sync::<AccountQuery>();
    assert_sync::<InitPrecheck>();
    assert_sync::<PaladinImportPrecheck>();
    assert_sync::<PaladinError>();
}
