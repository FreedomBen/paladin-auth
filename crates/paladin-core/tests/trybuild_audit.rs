// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase B trybuild driver: every `.rs` under `tests/trybuild/` is a
// compile-fail proof for the secret-bearing-type audit (docs/DESIGN.md §8
// / docs/IMPLEMENTATION_PLAN_01_CORE.md Phase B). The four cells are:
//
//   * `secret_not_debug.rs`        — `Secret: !Debug`
//   * `account_input_not_debug.rs` — `AccountInput: !Debug`
//   * `secret_not_serialize.rs`    — `Secret: !Serialize`
//   * `account_not_serialize.rs`   — `Account: !Serialize` (also
//     enforced when running `cargo test --features error-serde`,
//     since the feature only wires Serialize onto non-secret
//     projection types)
//
// Companion in-tree static assertions live in `tests/secret_audits.rs`
// so the same guarantee survives `TRYBUILD=skip` runs.

#[test]
fn secret_bearing_types_reject_debug_and_serialize() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/trybuild/secret_not_debug.rs");
    t.compile_fail("tests/trybuild/account_input_not_debug.rs");
    t.compile_fail("tests/trybuild/secret_not_serialize.rs");
    t.compile_fail("tests/trybuild/account_not_serialize.rs");
}
